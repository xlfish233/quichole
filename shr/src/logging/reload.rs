//! Hot reload support for runtime log level changes.
//!
//! This module provides the ability to reload log filters at runtime
//! without restarting the application.

use anyhow::{Context, Result};
use tracing_subscriber::Registry;

/// Handle for reloading log filters at runtime.
///
/// This handle allows dynamically changing log levels without
/// restarting the application. It can be used with environment
/// variables or configuration files.
pub struct ReloadHandle {
    handle: tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, Registry>,
}

impl ReloadHandle {
    /// Create a new reload handle from the underlying subscriber handle.
    pub fn new(
        handle: tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, Registry>,
    ) -> Self {
        Self { handle }
    }

    /// Reload the log filter with a new directive string.
    ///
    /// # Example
    /// ```
    /// # use quichole_shr::logging::ReloadHandle;
    /// # // ReloadHandle::new(...) would be created from subscriber setup
    /// # // let reload_handle = ReloadHandle::new(handle);
    /// # // reload_handle.reload("debug,my_crate=trace")?;
    /// ```
    pub fn reload(&self, directive: &str) -> Result<()> {
        self.handle
            .modify(|filter| {
                *filter = tracing_subscriber::EnvFilter::try_new(directive)
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::default());
            })
            .context("failed to reload log filter")?;
        Ok(())
    }

    /// Reload the log filter from the RUST_LOG environment variable.
    ///
    /// If RUST_LOG is not set, defaults to "info".
    pub fn reload_from_env(&self) -> Result<()> {
        let directive = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
        self.reload(&directive)
    }

    /// Reload the log filter from a LoggingConfig.
    ///
    /// This reconstructs the directive string from the configuration
    /// and applies it to the running subscriber.
    pub fn reload_from_config(&self, config: &crate::config::LoggingConfig) -> Result<()> {
        let directive = if config.filters.overrides.is_empty() {
            config.level.clone()
        } else {
            format!("{},{}", config.level, config.filters.overrides)
        };
        self.reload(&directive)
    }
}
