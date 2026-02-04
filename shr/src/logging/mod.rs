//! Logging initialization and configuration.
//!
//! This module provides two-phase initialization:
//! 1. `init_minimal_logging()` - called before config loading
//! 2. `init_logging()` - called after config loading with full settings
//!
//! # Two-Phase Initialization
//!
//! Phase 1 is used in `main()` before loading configuration to ensure early
//! logs (e.g., config parsing errors) are captured. Phase 2 installs the full production logging system.
//!
//! # Example
//!
//! ```ignore
//! // Phase 1: Before config
//! let _minimal_guard = init_minimal_logging();
//!
//! // Load config...
//! let config = load_config(path)?;
//!
//! // Phase 2: After config
//! let (_log_guard, _reload_handle) = init_logging(&config.logging)?;
//! ```

pub mod correlation;
pub mod redaction;
pub mod reload;

pub use correlation::{ConnectionId, StreamId};
pub use redaction::{redact_bytes_32, RedactedAuthDigest, RedactedNonce, RedactedSessionKey};
pub use reload::ReloadHandle;

use anyhow::{Context, Result};
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::broadcast;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    fmt::{self},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer, Registry,
};

use crate::config::LoggingConfig;

/// Guard that holds all WorkerGuards to ensure proper flushing on shutdown.
///
/// All WorkerGuards must be kept alive for the duration of the program
/// to ensure logs are flushed. This guard aggregates them all.
pub struct LogGuard {
    _guards: Vec<WorkerGuard>,
}

impl LogGuard {
    fn new(guards: Vec<Option<WorkerGuard>>) -> Self {
        Self {
            _guards: guards.into_iter().flatten().collect(),
        }
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        tracing::info!("flushing logs before shutdown");
    }
}

/// Phase 1: Initialize minimal logging before configuration is loaded.
pub fn init_minimal_logging() -> Option<WorkerGuard> {
    // Use atomic operation for thread-safe initialization check
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return None;
    }

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let (non_blocking, guard) = tracing_appender::non_blocking(io::stdout());

    let layer = fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_file(false)
        .with_line_number(false);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(layer)
        .init();

    Some(guard)
}

/// Phase 2: Initialize full logging system.
pub fn init_logging(config: &LoggingConfig) -> Result<(LogGuard, Option<ReloadHandle>)> {
    let env_filter = build_env_filter(config)?;

    if !config.console.enabled && !config.file.enabled {
        tracing::subscriber::set_global_default(Registry::default().with(env_filter)).ok();
        return Ok((LogGuard::new(vec![]), None));
    }

    let (filter_layer, reload_handle_obj) = tracing_subscriber::reload::Layer::new(env_filter);
    let reload_handle = ReloadHandle::new(reload_handle_obj);

    let mut guards = Vec::new();

    // Build subscriber inline to avoid type complexity
    let subscriber = build_subscriber_inline(config, filter_layer, &mut guards)?;

    tracing::subscriber::set_global_default(subscriber).ok();

    Ok((LogGuard::new(guards), Some(reload_handle)))
}

/// Build subscriber with all layers - done inline to avoid type erasure issues
fn build_subscriber_inline(
    config: &LoggingConfig,
    filter_layer: tracing_subscriber::reload::Layer<EnvFilter, Registry>,
    guards: &mut Vec<Option<WorkerGuard>>,
) -> Result<Box<dyn tracing::Subscriber + Send + Sync>> {
    // We need to handle different combinations of enabled features
    // This is verbose but avoids the type erasure problem

    match (config.console.enabled, config.file.enabled) {
        (true, true) => {
            // Both console and file
            let (console_non_blocking, console_guard) = if config.console.use_stderr {
                tracing_appender::non_blocking(io::stderr())
            } else {
                tracing_appender::non_blocking(io::stdout())
            };

            let log_dir = &config.file.directory;
            fs::create_dir_all(log_dir).with_context(|| {
                format!("failed to create log directory: {}", log_dir.display())
            })?;

            let rotation = match config.file.rotation_interval {
                crate::config::RotationInterval::Hourly => Rotation::HOURLY,
                crate::config::RotationInterval::Daily => Rotation::DAILY,
                crate::config::RotationInterval::Never => Rotation::NEVER,
            };

            let file_appender =
                RollingFileAppender::new(rotation.clone(), log_dir, &config.file.prefix);
            let (file_non_blocking, file_guard) = tracing_appender::non_blocking(file_appender);

            guards.push(Some(console_guard));
            guards.push(Some(file_guard));

            let console_layer = match config.format {
                crate::config::LogFormat::Json => fmt::layer()
                    .json()
                    .with_writer(console_non_blocking)
                    .with_target(config.with_target)
                    .with_file(config.with_file_location)
                    .with_line_number(config.with_file_location)
                    .boxed(),
                crate::config::LogFormat::Pretty => fmt::layer()
                    .pretty()
                    .with_writer(console_non_blocking)
                    .with_target(config.with_target)
                    .with_file(config.with_file_location)
                    .with_line_number(config.with_file_location)
                    .with_ansi(config.console.ansi)
                    .boxed(),
            };

            let file_layer = fmt::layer()
                .with_writer(file_non_blocking)
                .with_target(config.with_target)
                .with_file(config.with_file_location)
                .with_line_number(config.with_file_location)
                .boxed();

            if config.file.separate_error_log {
                let error_prefix = format!("{}-error", config.file.prefix);
                let error_appender = RollingFileAppender::new(rotation, log_dir, &error_prefix);
                let (error_non_blocking, error_guard) =
                    tracing_appender::non_blocking(error_appender);
                guards.push(Some(error_guard));

                let error_layer = fmt::layer()
                    .with_writer(error_non_blocking)
                    .with_filter(EnvFilter::new("warn"))
                    .boxed();

                Ok(Box::new(
                    Registry::default()
                        .with(filter_layer)
                        .with(console_layer)
                        .with(file_layer)
                        .with(error_layer),
                ))
            } else {
                Ok(Box::new(
                    Registry::default()
                        .with(filter_layer)
                        .with(console_layer)
                        .with(file_layer),
                ))
            }
        }
        (true, false) => {
            // Only console
            let (non_blocking, guard) = if config.console.use_stderr {
                tracing_appender::non_blocking(io::stderr())
            } else {
                tracing_appender::non_blocking(io::stdout())
            };
            guards.push(Some(guard));

            let layer = match config.format {
                crate::config::LogFormat::Json => fmt::layer()
                    .json()
                    .with_writer(non_blocking)
                    .with_target(config.with_target)
                    .with_file(config.with_file_location)
                    .with_line_number(config.with_file_location)
                    .boxed(),
                crate::config::LogFormat::Pretty => fmt::layer()
                    .pretty()
                    .with_writer(non_blocking)
                    .with_target(config.with_target)
                    .with_file(config.with_file_location)
                    .with_line_number(config.with_file_location)
                    .with_ansi(config.console.ansi)
                    .boxed(),
            };

            Ok(Box::new(Registry::default().with(filter_layer).with(layer)))
        }
        (false, true) => {
            // Only file
            let log_dir = &config.file.directory;
            fs::create_dir_all(log_dir).with_context(|| {
                format!("failed to create log directory: {}", log_dir.display())
            })?;

            let rotation = match config.file.rotation_interval {
                crate::config::RotationInterval::Hourly => Rotation::HOURLY,
                crate::config::RotationInterval::Daily => Rotation::DAILY,
                crate::config::RotationInterval::Never => Rotation::NEVER,
            };

            let file_appender =
                RollingFileAppender::new(rotation.clone(), log_dir, &config.file.prefix);
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            guards.push(Some(guard));

            let file_layer = fmt::layer()
                .with_writer(non_blocking)
                .with_target(config.with_target)
                .with_file(config.with_file_location)
                .with_line_number(config.with_file_location)
                .boxed();

            if config.file.separate_error_log {
                let error_prefix = format!("{}-error", config.file.prefix);
                let error_appender = RollingFileAppender::new(rotation, log_dir, &error_prefix);
                let (error_non_blocking, error_guard) =
                    tracing_appender::non_blocking(error_appender);
                guards.push(Some(error_guard));

                let error_layer = fmt::layer()
                    .with_writer(error_non_blocking)
                    .with_filter(EnvFilter::new("warn"))
                    .boxed();

                Ok(Box::new(
                    Registry::default()
                        .with(filter_layer)
                        .with(file_layer)
                        .with(error_layer),
                ))
            } else {
                Ok(Box::new(
                    Registry::default().with(filter_layer).with(file_layer),
                ))
            }
        }
        (false, false) => {
            // Nothing - should have been caught earlier
            Ok(Box::new(Registry::default().with(filter_layer)))
        }
    }
}

fn build_env_filter(config: &LoggingConfig) -> Result<EnvFilter> {
    let filter = if let Ok(rust_log) = std::env::var("RUST_LOG") {
        let mut filter = EnvFilter::try_new(rust_log).context("invalid RUST_LOG format")?;

        if !config.filters.overrides.is_empty() {
            filter = filter.add_directive(
                config
                    .filters
                    .overrides
                    .parse()
                    .context("invalid filter overrides in config")?,
            );
        }

        filter
    } else {
        let directive = if config.filters.overrides.is_empty() {
            config.level.clone()
        } else {
            format!("{},{}", config.level, config.filters.overrides)
        };

        EnvFilter::try_new(directive).context("invalid log level configuration")?
    };

    Ok(filter)
}

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Shutdown signal for graceful shutdown coordination.
///
/// Uses a broadcast channel to notify all listeners when shutdown is initiated.
/// Clone this type to pass to multiple tasks/components.
#[derive(Clone)]
pub struct ShutdownSignal {
    tx: broadcast::Sender<()>,
}

impl ShutdownSignal {
    /// Create a new shutdown signal.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1);
        Self { tx }
    }

    /// Subscribe to shutdown notifications.
    ///
    /// Returns a receiver that will receive `()` when shutdown is triggered.
    /// Callers should call `.recv()` or `.await` on the receiver.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    /// Trigger shutdown.
    ///
    /// This notifies all subscribers that shutdown should begin.
    /// Safe to call multiple times (idempotent).
    pub fn shutdown(&self) {
        let _ = self.tx.send(());
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_minimal_logging() {
        let guard = init_minimal_logging();
        assert!(guard.is_some());

        let guard2 = init_minimal_logging();
        assert!(guard2.is_none());
    }

    #[test]
    fn test_build_env_filter() {
        let config = LoggingConfig::default();
        let filter = build_env_filter(&config).unwrap();
        assert!(filter.to_string().contains("info"));
    }

    #[test]
    fn test_shutdown_signal_basic() {
        let shutdown = ShutdownSignal::new();
        let mut rx = shutdown.subscribe();

        shutdown.shutdown();

        // Should receive immediately
        let result = rx.try_recv();
        assert!(result.is_ok());
    }

    #[test]
    fn test_shutdown_signal_multiple_subscribers() {
        let shutdown = ShutdownSignal::new();
        let mut rx1 = shutdown.subscribe();
        let mut rx2 = shutdown.subscribe();

        shutdown.shutdown();

        // Both should receive
        assert!(rx1.try_recv().is_ok());
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn test_shutdown_signal_clone() {
        let shutdown = ShutdownSignal::new();
        let shutdown_clone = shutdown.clone();
        let mut rx = shutdown_clone.subscribe();

        shutdown.shutdown();

        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn test_shutdown_signal_default() {
        let shutdown = ShutdownSignal::default();
        let mut rx = shutdown.subscribe();

        shutdown.shutdown();

        assert!(rx.try_recv().is_ok());
    }
}
