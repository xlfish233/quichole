use quichole_shr::config::{ClientServiceConfig, ServiceType};

#[derive(Debug, Clone)]
pub struct ClientService {
    name: String,
    token: String,
    local_addr: String,
    service_type: ServiceType,
    retry_interval: Option<u64>,
}

impl ClientService {
    pub fn from_config(name: String, config: &ClientServiceConfig) -> Self {
        Self {
            name,
            token: config.token.clone(),
            local_addr: config.local_addr.clone(),
            service_type: config.service_type,
            retry_interval: config.retry_interval,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }

    pub const fn service_type(&self) -> ServiceType {
        self.service_type
    }

    pub const fn retry_interval(&self) -> Option<u64> {
        self.retry_interval
    }
}
