use anyhow::{bail, Result};
use quichole_shr::config::ServerConfig;

use crate::service::Service;
use std::collections::HashMap;

#[derive(Debug)]
pub struct ServerState {
    config: ServerConfig,
    services: HashMap<String, Service>,
    digest_index: HashMap<[u8; 32], String>,
}

impl ServerState {
    pub fn from_config(mut config: ServerConfig) -> Result<Self> {
        config.validate()?;

        let mut services = HashMap::new();
        let mut digest_index = HashMap::new();

        for (name, service_cfg) in &config.services {
            let service = Service::from_config(name.clone(), service_cfg);
            let digest = *service.digest();
            if let Some(existing) = digest_index.insert(digest, name.clone()) {
                bail!("duplicate service digest for '{}' and '{}'", existing, name);
            }
            services.insert(name.clone(), service);
        }

        Ok(Self {
            config,
            services,
            digest_index,
        })
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn services_len(&self) -> usize {
        self.services.len()
    }

    pub fn service(&self, name: &str) -> Option<&Service> {
        self.services.get(name)
    }

    pub fn service_by_digest(&self, digest: &[u8; 32]) -> Option<&Service> {
        self.digest_index
            .get(digest)
            .and_then(|name| self.services.get(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quichole_shr::protocol::service_digest;

    #[test]
    fn test_server_state_builds_services() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"

            [services.http]
            bind_addr = "0.0.0.0:8080"
            token = "http_token"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        let server = ServerState::from_config(config).unwrap();

        assert_eq!(server.services_len(), 2);
        let ssh = server.service("ssh").unwrap();
        assert_eq!(ssh.token(), "default_secret");
        assert_eq!(ssh.bind_addr(), "0.0.0.0:2222");
        assert_eq!(ssh.service_type(), quichole_shr::config::ServiceType::Tcp);
        let http = server.service("http").unwrap();
        assert_eq!(http.token(), "http_token");
        assert_eq!(server.config().bind_addr, "0.0.0.0:4433");
    }

    #[test]
    fn test_server_state_lookup_by_digest() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        let server = ServerState::from_config(config).unwrap();

        let digest = service_digest("ssh");
        let service = server.service_by_digest(&digest).unwrap();
        assert_eq!(service.name(), "ssh");
    }

    #[test]
    fn test_server_state_rejects_missing_token() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = ServerState::from_config(config);

        assert!(result.is_err());
    }
}
