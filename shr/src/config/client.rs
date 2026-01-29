// 客户端配置
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{ServiceType, TlsConfig};

/// 客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// 服务端地址
    pub remote_addr: String,

    /// 心跳超时（秒）
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: u64,

    /// 重试间隔（秒）
    #[serde(default = "default_retry_interval")]
    pub retry_interval: u64,

    /// 默认 token（可选）
    #[serde(default)]
    pub default_token: Option<String>,

    /// TLS 配置
    #[serde(default)]
    pub tls: TlsConfig,

    /// 服务列表
    pub services: HashMap<String, ClientServiceConfig>,
}

/// 客户端服务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientServiceConfig {
    /// 本地服务地址
    pub local_addr: String,

    /// 认证 token
    #[serde(default)]
    pub token: String,

    /// 服务类型
    #[serde(default, rename = "type")]
    pub service_type: ServiceType,

    /// 针对该服务的重试间隔（秒），可覆盖全局 retry_interval
    #[serde(default)]
    pub retry_interval: Option<u64>,
}

fn default_heartbeat_timeout() -> u64 {
    40
}

fn default_retry_interval() -> u64 {
    1
}

impl ClientConfig {
    pub fn validate(&mut self) -> Result<()> {
        if self.remote_addr.trim().is_empty() {
            bail!("client remote_addr is empty");
        }
        if self.heartbeat_timeout == 0 {
            bail!("client heartbeat_timeout must be > 0");
        }
        if self.retry_interval == 0 {
            bail!("client retry_interval must be > 0");
        }
        if self.services.is_empty() {
            bail!("client services is empty");
        }

        let default_token = self
            .default_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .map(str::to_string);

        for (name, service) in &mut self.services {
            if service.local_addr.trim().is_empty() {
                bail!("client service '{}' local_addr is empty", name);
            }
            if let Some(retry_interval) = service.retry_interval {
                if retry_interval == 0 {
                    bail!("client service '{}' retry_interval must be > 0", name);
                }
            }
            if service.token.is_empty() {
                if let Some(token) = &default_token {
                    service.token = token.clone();
                } else {
                    bail!(
                        "client service '{}' token is empty and no default_token",
                        name
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_parsing() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            heartbeat_timeout = 40
            retry_interval = 1

            [services.ssh]
            token = "secret_token"
            local_addr = "127.0.0.1:22"
            type = "tcp"
        "#;

        let config: ClientConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.remote_addr, "example.com:4433");
        assert_eq!(config.heartbeat_timeout, 40);
        assert_eq!(config.retry_interval, 1);
        assert_eq!(config.services.len(), 1);

        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "secret_token");
        assert_eq!(ssh_service.local_addr, "127.0.0.1:22");
        assert_eq!(ssh_service.service_type, ServiceType::Tcp);
    }

    #[test]
    fn test_client_config_with_default_token() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            default_token = "default_secret"

            [services.ssh]
            local_addr = "127.0.0.1:22"
        "#;

        let config: ClientConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.default_token, Some("default_secret".to_string()));

        let ssh_service = config.services.get("ssh").unwrap();
        // token 应该为空，等待验证时填充
        assert_eq!(ssh_service.token, "");
    }

    #[test]
    fn test_client_config_defaults() {
        let toml_str = r#"
            remote_addr = "example.com:4433"

            [services.ssh]
            token = "secret"
            local_addr = "127.0.0.1:22"
        "#;

        let config: ClientConfig = toml::from_str(toml_str).unwrap();

        // 默认值
        assert_eq!(config.heartbeat_timeout, 40);
        assert_eq!(config.retry_interval, 1);
    }

    #[test]
    fn test_client_config_multiple_services() {
        let toml_str = r#"
            remote_addr = "example.com:4433"

            [services.ssh]
            token = "ssh_token"
            local_addr = "127.0.0.1:22"

            [services.http]
            token = "http_token"
            local_addr = "127.0.0.1:8080"

            [services.dns]
            token = "dns_token"
            local_addr = "127.0.0.1:53"
            type = "udp"
        "#;

        let config: ClientConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.services.len(), 3);
        assert!(config.services.contains_key("ssh"));
        assert!(config.services.contains_key("http"));
        assert!(config.services.contains_key("dns"));
    }

    #[test]
    fn test_client_service_retry_interval() {
        let toml_str = r#"
            remote_addr = "example.com:4433"

            [services.ssh]
            token = "token"
            local_addr = "127.0.0.1:22"
            retry_interval = 5
        "#;

        let config: ClientConfig = toml::from_str(toml_str).unwrap();
        let service = config.services.get("ssh").unwrap();

        assert_eq!(service.retry_interval, Some(5));
    }

    #[test]
    fn test_client_config_validation_fill_default_token() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            default_token = "default_secret"

            [services.ssh]
            local_addr = "127.0.0.1:22"
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        config.validate().unwrap();

        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "default_secret");
    }

    #[test]
    fn test_client_config_validation_missing_token() {
        let toml_str = r#"
            remote_addr = "example.com:4433"

            [services.ssh]
            local_addr = "127.0.0.1:22"
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_client_config_validation_empty_remote_addr() {
        let toml_str = r#"
            remote_addr = ""

            [services.ssh]
            token = "token"
            local_addr = "127.0.0.1:22"
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_client_config_validation_empty_services() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            services = {}
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_client_config_validation_empty_service_local_addr() {
        let toml_str = r#"
            remote_addr = "example.com:4433"

            [services.ssh]
            token = "token"
            local_addr = ""
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_client_config_validation_zero_heartbeat_timeout() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            heartbeat_timeout = 0

            [services.ssh]
            token = "token"
            local_addr = "127.0.0.1:22"
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_client_config_validation_zero_retry_interval() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            retry_interval = 0

            [services.ssh]
            token = "token"
            local_addr = "127.0.0.1:22"
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_client_service_validation_zero_retry_interval() {
        let toml_str = r#"
            remote_addr = "example.com:4433"

            [services.ssh]
            token = "token"
            local_addr = "127.0.0.1:22"
            retry_interval = 0
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }
}
