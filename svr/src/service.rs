use quichole_shr::config::{ServerServiceConfig, ServiceType};
use quichole_shr::protocol::service_digest;

#[derive(Debug, Clone)]
pub struct Service {
    name: String,
    token: String,
    bind_addr: String,
    service_type: ServiceType,
    digest: [u8; 32],
}

impl Service {
    pub fn from_config(name: String, config: &ServerServiceConfig) -> Self {
        Self {
            digest: service_digest(&name),
            name,
            token: config.token.clone(),
            bind_addr: config.bind_addr.clone(),
            service_type: config.service_type,
        }
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }

    pub const fn service_type(&self) -> ServiceType {
        self.service_type
    }
}
