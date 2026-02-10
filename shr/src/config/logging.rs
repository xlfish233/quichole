//! Logging configuration structures.
//!
//! This module defines the configuration schema for the logging system,
//! supporting console and file output, log rotation, filtering, and
//! sensitive data redaction.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LoggingConfig {
    /// Primary log level: trace, debug, info, warn, error
    #[serde(default = "default_level")]
    pub level: String,

    /// Log format: pretty or json
    #[serde(default = "default_format")]
    pub format: LogFormat,

    /// Whether to include source file and line number in logs
    #[serde(default = "default_with_file_location")]
    pub with_file_location: bool,

    /// Whether to include target (module path) in logs
    #[serde(default = "default_with_target")]
    pub with_target: bool,

    /// Console output configuration
    #[serde(default)]
    pub console: ConsoleConfig,

    /// File output configuration
    #[serde(default)]
    pub file: FileConfig,

    /// Per-module log filtering
    #[serde(default)]
    pub filters: FiltersConfig,

    /// Sensitive data redaction settings
    #[serde(default)]
    pub redaction: RedactionConfig,

    /// Performance metrics logging
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Async logging configuration (backpressure handling)
    #[serde(default)]
    pub r#async: AsyncConfig,
}

impl LoggingConfig {
    /// Validate the logging configuration.
    ///
    /// Returns an error if:
    /// - The log level is invalid
    /// - The file directory is invalid
    /// - The rotation size is zero
    /// - The retention count is zero
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        // Validate log level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.level.as_str()) {
            anyhow::bail!(
                "invalid log level '{}': must be one of {}",
                self.level,
                valid_levels.join(", ")
            );
        }

        // Validate file configuration
        if self.file.enabled {
            if self.file.rotation_size == 0 {
                anyhow::bail!("rotation_size must be greater than zero");
            }
            if self.file.retention_count == 0 {
                anyhow::bail!("retention_count must be greater than zero");
            }
        }

        // Validate metrics interval
        if self.metrics.enabled && self.metrics.interval_seconds == 0 {
            anyhow::bail!("metrics.interval_seconds must be greater than zero");
        }

        // Validate async buffer size
        if self.r#async.buffer_size == 0 {
            anyhow::bail!("async.buffer_size must be greater than zero");
        }

        Ok(())
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            format: default_format(),
            with_file_location: default_with_file_location(),
            with_target: default_with_target(),
            console: Default::default(),
            file: Default::default(),
            filters: Default::default(),
            redaction: Default::default(),
            metrics: Default::default(),
            r#async: Default::default(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable pretty format with ANSI colors
    #[default]
    Pretty,
    /// Machine-parseable JSON format
    Json,
}

/// Console output configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ConsoleConfig {
    /// Enable console logging
    #[serde(default = "default_console_enabled")]
    pub enabled: bool,

    /// Write to stderr instead of stdout
    #[serde(default)]
    pub use_stderr: bool,

    /// Enable ANSI color codes (only affects pretty format)
    #[serde(default = "default_console_ansi")]
    pub ansi: bool,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            enabled: default_console_enabled(),
            use_stderr: false,
            ansi: default_console_ansi(),
        }
    }
}

/// File output configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FileConfig {
    /// Enable file logging
    #[serde(default)]
    pub enabled: bool,

    /// Directory for log files (absolute path or relative to config file)
    #[serde(default = "default_file_directory")]
    pub directory: PathBuf,

    /// Base name for log file (will be appended with .log)
    #[serde(default = "default_file_prefix")]
    pub prefix: String,

    /// Maximum size of each log file before rotation (in bytes)
    #[serde(default = "default_rotation_size")]
    pub rotation_size: u64,

    /// Time-based rotation interval
    #[serde(default)]
    pub rotation_interval: RotationInterval,

    /// Maximum number of rotated log files to keep
    #[serde(default = "default_retention_count")]
    pub retention_count: usize,

    /// Create a separate error-only log file
    #[serde(default)]
    pub separate_error_log: bool,

    /// Minimum log level for file output
    #[serde(default = "default_file_level")]
    pub level: String,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: default_file_directory(),
            prefix: default_file_prefix(),
            rotation_size: default_rotation_size(),
            rotation_interval: Default::default(),
            retention_count: default_retention_count(),
            separate_error_log: false,
            level: default_file_level(),
        }
    }
}

/// Time-based log rotation interval.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RotationInterval {
    /// Rotate logs hourly
    Hourly,
    /// Rotate logs daily
    #[default]
    Daily,
    /// Never rotate based on time
    Never,
}

/// Per-module log filtering configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FiltersConfig {
    /// Override log levels for specific crates/modules.
    ///
    /// Format: "crate=level,crate::module=level"
    /// Example: "quichole_svr=debug,tokio=warn,quichole_svr::handshake=trace"
    #[serde(default)]
    pub overrides: String,
}

/// Sensitive data redaction configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RedactionConfig {
    /// Enable redaction of sensitive data
    #[serde(default = "default_redaction_enabled")]
    pub enabled: bool,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: default_redaction_enabled(),
        }
    }
}

/// Performance metrics logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MetricsConfig {
    /// Enable periodic performance metrics logging
    #[serde(default)]
    pub enabled: bool,

    /// Interval for metrics logging (seconds)
    #[serde(default = "default_metrics_interval")]
    pub interval_seconds: u64,

    /// Include connection statistics
    #[serde(default = "default_metrics_include_connection")]
    pub include_connection_stats: bool,

    /// Include memory usage (requires additional dependency)
    #[serde(default)]
    pub include_memory_stats: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: default_metrics_interval(),
            include_connection_stats: default_metrics_include_connection(),
            include_memory_stats: false,
        }
    }
}

/// Async logging configuration for backpressure handling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AsyncConfig {
    /// Buffer size for non-blocking writer (number of log lines)
    #[serde(default = "default_async_buffer_size")]
    pub buffer_size: usize,

    /// Behavior when buffer is full
    #[serde(default)]
    pub backpressure_behavior: BackpressureBehavior,
}

impl Default for AsyncConfig {
    fn default() -> Self {
        Self {
            buffer_size: default_async_buffer_size(),
            backpressure_behavior: Default::default(),
        }
    }
}

/// Backpressure behavior when the log buffer is full.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BackpressureBehavior {
    /// Block until buffer space is available (prevents log loss)
    #[default]
    Block,
    /// Drop log lines when buffer is full (prevents blocking)
    Drop,
}

// ============================================================================
// Default Value Functions
// ============================================================================

fn default_level() -> String {
    "info".to_string()
}

fn default_format() -> LogFormat {
    LogFormat::Pretty
}

fn default_with_file_location() -> bool {
    false
}

fn default_with_target() -> bool {
    true
}

fn default_console_enabled() -> bool {
    true
}

fn default_console_ansi() -> bool {
    true
}

fn default_file_directory() -> PathBuf {
    PathBuf::from("./logs")
}

fn default_file_prefix() -> String {
    "quichole".to_string()
}

fn default_rotation_size() -> u64 {
    // 100 MB
    100 * 1024 * 1024
}

fn default_retention_count() -> usize {
    30
}

fn default_file_level() -> String {
    "debug".to_string()
}

fn default_redaction_enabled() -> bool {
    true
}

fn default_metrics_interval() -> u64 {
    60
}

fn default_metrics_include_connection() -> bool {
    true
}

fn default_async_buffer_size() -> usize {
    // Default buffer size for tracing-appender non-blocking writer
    // This is typically sufficient for most workloads
    1024
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_logging_config() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, "info");
        assert_eq!(config.format, LogFormat::Pretty);
        assert!(!config.with_file_location);
        assert!(config.with_target);
        assert!(config.console.enabled);
        assert!(!config.file.enabled);
        assert!(config.redaction.enabled);
        assert!(!config.metrics.enabled);
    }

    #[test]
    fn test_logging_config_validation_valid() {
        let config = LoggingConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_logging_config_validation_invalid_level() {
        let config = LoggingConfig {
            level: "invalid".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_logging_config_validation_zero_rotation_size() {
        let mut config = LoggingConfig::default();
        config.file.enabled = true;
        config.file.rotation_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_logging_config_validation_zero_retention() {
        let mut config = LoggingConfig::default();
        config.file.enabled = true;
        config.file.retention_count = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_logging_config_validation_zero_metrics_interval() {
        let mut config = LoggingConfig::default();
        config.metrics.enabled = true;
        config.metrics.interval_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_logging_config_validation_zero_buffer_size() {
        let mut config = LoggingConfig::default();
        config.r#async.buffer_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_complete_logging_config_from_toml() {
        let toml_str = r#"
            level = "debug"
            format = "json"
            with_file_location = true
            with_target = false

            [console]
            enabled = true
            use_stderr = true
            ansi = false

            [file]
            enabled = true
            directory = "/var/log/quichole"
            prefix = "server"
            rotation_size = 52428800
            rotation_interval = "hourly"
            retention_count = 14
            separate_error_log = true
            level = "trace"

            [filters]
            overrides = "quichole_svr=trace,tokio=info"

            [redaction]
            enabled = true

            [metrics]
            enabled = true
            interval_seconds = 30
            include_connection_stats = true
            include_memory_stats = true

            [async]
            buffer_size = 2048
            backpressure_behavior = "drop"
        "#;

        let config: LoggingConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.level, "debug");
        assert_eq!(config.format, LogFormat::Json);
        assert!(config.with_file_location);
        assert!(!config.with_target);
        assert!(config.console.use_stderr);
        assert!(!config.console.ansi);
        assert!(config.file.enabled);
        assert_eq!(config.file.directory, PathBuf::from("/var/log/quichole"));
        assert_eq!(config.file.prefix, "server");
        assert_eq!(config.file.rotation_size, 52428800);
        assert_eq!(config.file.rotation_interval, RotationInterval::Hourly);
        assert_eq!(config.file.retention_count, 14);
        assert!(config.file.separate_error_log);
        assert_eq!(config.file.level, "trace");
        assert_eq!(config.filters.overrides, "quichole_svr=trace,tokio=info");
        assert!(config.redaction.enabled);
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.interval_seconds, 30);
        assert!(config.metrics.include_memory_stats);
        assert_eq!(config.r#async.buffer_size, 2048);
        assert_eq!(
            config.r#async.backpressure_behavior,
            BackpressureBehavior::Drop
        );

        // Validate the config
        assert!(config.validate().is_ok());
    }
}
