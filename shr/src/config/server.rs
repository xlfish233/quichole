// 服务端配置
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{LoggingConfig, ServiceType, TlsConfig};

/// 服务端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 服务端监听地址
    pub bind_addr: String,

    /// 心跳间隔（秒）
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,

    /// 心跳 ACK 超时（秒，默认 heartbeat_interval * 3）
    #[serde(default)]
    pub heartbeat_ack_timeout: Option<u64>,

    /// QUIC 空闲超时（毫秒，可选）
    #[serde(default)]
    pub quic_idle_timeout_ms: Option<u64>,

    /// 默认 token（可选）
    #[serde(default)]
    pub default_token: Option<String>,

    /// TLS 配置
    #[serde(default)]
    pub tls: TlsConfig,

    /// 日志配置
    #[serde(default)]
    pub logging: LoggingConfig,

    /// 服务列表
    pub services: HashMap<String, ServerServiceConfig>,
}

/// 服务端服务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerServiceConfig {
    /// 服务暴露地址
    pub bind_addr: String,

    /// 认证 token
    #[serde(default)]
    pub token: String,

    /// 服务类型
    #[serde(default, rename = "type")]
    pub service_type: ServiceType,
}

fn default_heartbeat_interval() -> u64 {
    30
}

impl ServerConfig {
    pub fn validate(&mut self) -> Result<()> {
        if self.bind_addr.trim().is_empty() {
            bail!("server bind_addr is empty");
        }
        if self.heartbeat_interval == 0 {
            bail!("server heartbeat_interval must be > 0");
        }
        if let Some(ack_timeout) = self.heartbeat_ack_timeout {
            if ack_timeout == 0 {
                bail!("server heartbeat_ack_timeout must be > 0");
            }
        } else {
            let default_ack = self.heartbeat_interval.saturating_mul(3).max(3);
            self.heartbeat_ack_timeout = Some(default_ack);
        }
        if let Some(idle_timeout) = self.quic_idle_timeout_ms {
            if idle_timeout == 0 {
                bail!("server quic_idle_timeout_ms must be > 0");
            }
        }
        if self.services.is_empty() {
            bail!("server services is empty");
        }

        let default_token = self
            .default_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .map(str::to_string);

        for (name, service) in &mut self.services {
            if service.bind_addr.trim().is_empty() {
                bail!("server service '{}' bind_addr is empty", name);
            }
            if service.token.is_empty() {
                if let Some(token) = &default_token {
                    service.token = token.clone();
                } else {
                    bail!(
                        "server service '{}' token is empty and no default_token",
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
    fn test_server_config_parsing() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            heartbeat_interval = 30
            heartbeat_ack_timeout = 120
            quic_idle_timeout_ms = 5000

            [services.ssh]
            token = "secret_token"
            bind_addr = "0.0.0.0:2222"
            type = "tcp"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.bind_addr, "0.0.0.0:4433");
        assert_eq!(config.heartbeat_interval, 30);
        assert_eq!(config.heartbeat_ack_timeout, Some(120));
        assert_eq!(config.quic_idle_timeout_ms, Some(5000));
        assert_eq!(config.services.len(), 1);

        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "secret_token");
        assert_eq!(ssh_service.bind_addr, "0.0.0.0:2222");
        assert_eq!(ssh_service.service_type, ServiceType::Tcp);
    }

    #[test]
    fn test_server_config_with_default_token() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.default_token, Some("default_secret".to_string()));

        let ssh_service = config.services.get("ssh").unwrap();
        // token 应该为空，等待验证时填充
        assert_eq!(ssh_service.token, "");
    }

    #[test]
    fn test_server_config_default_heartbeat() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"

            [services.ssh]
            token = "secret"
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        config.validate().unwrap();

        // 默认心跳间隔应该是 30 秒
        assert_eq!(config.heartbeat_interval, 30);
        assert_eq!(config.heartbeat_ack_timeout, Some(90));
        assert_eq!(config.quic_idle_timeout_ms, None);
    }

    #[test]
    fn test_server_config_multiple_services() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"

            [services.ssh]
            token = "ssh_token"
            bind_addr = "0.0.0.0:2222"

            [services.http]
            token = "http_token"
            bind_addr = "0.0.0.0:8080"
            type = "tcp"

            [services.dns]
            token = "dns_token"
            bind_addr = "0.0.0.0:5353"
            type = "udp"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.services.len(), 3);
        assert!(config.services.contains_key("ssh"));
        assert!(config.services.contains_key("http"));
        assert!(config.services.contains_key("dns"));

        let dns_service = config.services.get("dns").unwrap();
        assert_eq!(dns_service.service_type, ServiceType::Udp);
    }

    #[test]
    fn test_service_type_default() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"

            [services.test]
            token = "token"
            bind_addr = "0.0.0.0:8080"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        let service = config.services.get("test").unwrap();

        // 默认应该是 TCP
        assert_eq!(service.service_type, ServiceType::Tcp);
    }

    #[test]
    fn test_service_type_serialization() {
        #[derive(Serialize)]
        struct Wrap {
            #[serde(rename = "type")]
            ty: ServiceType,
        }

        let tcp = Wrap {
            ty: ServiceType::Tcp,
        };
        let udp = Wrap {
            ty: ServiceType::Udp,
        };

        assert!(toml::to_string(&tcp).unwrap().contains("type = \"tcp\""));
        assert!(toml::to_string(&udp).unwrap().contains("type = \"udp\""));
    }

    #[test]
    fn test_server_config_validation_fill_default_token() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        config.validate().unwrap();

        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "default_secret");
    }

    #[test]
    fn test_server_config_validation_missing_token() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_server_config_validation_empty_bind_addr() {
        let toml_str = r#"
            bind_addr = ""

            [services.ssh]
            token = "token"
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_server_config_validation_empty_services() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            services = {}
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_server_config_validation_empty_service_bind_addr() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"

            [services.ssh]
            token = "token"
            bind_addr = ""
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_server_config_validation_zero_heartbeat_interval() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            heartbeat_interval = 0

            [services.ssh]
            token = "token"
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_server_config_validation_zero_heartbeat_ack_timeout() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            heartbeat_ack_timeout = 0

            [services.ssh]
            token = "token"
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }

    #[test]
    fn test_server_config_validation_zero_quic_idle_timeout() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            quic_idle_timeout_ms = 0

            [services.ssh]
            token = "token"
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }
}
