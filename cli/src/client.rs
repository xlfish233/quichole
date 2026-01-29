use anyhow::Result;
use quichole_shr::config::ClientConfig;
use std::collections::HashMap;

use crate::service::ClientService;

#[derive(Debug)]
pub struct ClientState {
    config: ClientConfig,
    services: HashMap<String, ClientService>,
}

impl ClientState {
    pub fn from_config(mut config: ClientConfig) -> Result<Self> {
        config.validate()?;

        let mut services = HashMap::new();
        for (name, service_cfg) in &config.services {
            let service = ClientService::from_config(name.clone(), service_cfg);
            services.insert(name.clone(), service);
        }

        Ok(Self { config, services })
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn services_len(&self) -> usize {
        self.services.len()
    }

    pub fn service(&self, name: &str) -> Option<&ClientService> {
        self.services.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quichole_shr::config::ServiceType;

    #[test]
    fn test_client_state_builds_services() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            default_token = "default_secret"

            [services.ssh]
            local_addr = "127.0.0.1:22"

            [services.dns]
            local_addr = "127.0.0.1:53"
            type = "udp"
        "#;

        let config: quichole_shr::config::ClientConfig = toml::from_str(toml_str).unwrap();
        let client = ClientState::from_config(config).unwrap();

        assert_eq!(client.services_len(), 2);
        let ssh = client.service("ssh").unwrap();
        assert_eq!(ssh.token(), "default_secret");
        assert_eq!(ssh.local_addr(), "127.0.0.1:22");
        assert_eq!(ssh.service_type(), ServiceType::Tcp);
    }
}
