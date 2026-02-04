use anyhow::{bail, Context, Result};
use quichole_shr::config::ServiceType;
use quichole_shr::crypto::verify_auth_digest;
use quichole_shr::logging::{RedactedNonce, RedactedSessionKey};
use quichole_shr::protocol::{
    generate_nonce, generate_session_key, Auth, ControlChannelCmd, DataChannelCmd, Hello, PROTO_V1,
};
use std::collections::HashMap;

use crate::server::ServerState;
use crate::service::Service;

pub struct ControlHandshake {
    service: Service,
    nonce: [u8; 32],
}

impl ControlHandshake {
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub fn verify_auth(self, auth: &Auth) -> Result<ControlSession> {
        if !verify_auth_digest(&auth.digest, self.service.token(), &self.nonce) {
            bail!("auth failed");
        }

        Ok(ControlSession {
            service: self.service,
            data_channels: DataChannelManager::default(),
        })
    }
}

#[derive(Default)]
struct DataChannelManager {
    pending: HashMap<[u8; 32], ServiceType>,
}

impl DataChannelManager {
    fn create_request(&mut self, service_type: ServiceType) -> [u8; 32] {
        let session_key = generate_session_key();
        tracing::debug!(
            session_key = %RedactedSessionKey(session_key),
            "server generated session key for data channel"
        );
        self.pending.insert(session_key, service_type);
        session_key
    }

    fn accept_hello(&mut self, hello: &Hello) -> Result<DataChannelCmd> {
        let (version, session_key) = match hello {
            Hello::DataChannelHello {
                version,
                session_key,
            } => (*version, session_key),
            _ => bail!("unexpected hello type for data channel"),
        };

        if version != PROTO_V1 {
            bail!("protocol version mismatch");
        }

        let service_type = self
            .pending
            .remove(session_key)
            .context("unknown session key")?;

        Ok(match service_type {
            ServiceType::Tcp => DataChannelCmd::StartForwardTcp,
            ServiceType::Udp => DataChannelCmd::StartForwardUdp,
        })
    }
}

pub struct ControlSession {
    service: Service,
    data_channels: DataChannelManager,
}

impl ControlSession {
    pub fn service(&self) -> &Service {
        &self.service
    }

    pub fn create_data_channel(&mut self) -> (ControlChannelCmd, [u8; 32]) {
        let session_key = self
            .data_channels
            .create_request(self.service.service_type());
        (ControlChannelCmd::CreateDataChannel, session_key)
    }

    pub fn accept_data_channel_hello(&mut self, hello: &Hello) -> Result<DataChannelCmd> {
        self.data_channels.accept_hello(hello)
    }
}

pub fn begin_control_handshake(server: &ServerState, hello: &Hello) -> Result<ControlHandshake> {
    let (version, service_digest) = match hello {
        Hello::ControlChannelHello {
            version,
            service_digest,
        } => (*version, service_digest),
        _ => bail!("unexpected hello type for control channel"),
    };

    if version != PROTO_V1 {
        bail!("protocol version mismatch");
    }

    tracing::debug!(
        service_digest = %format!("{:02x}***", service_digest[0]),
        "looking up service by digest"
    );

    let service = server
        .service_by_digest(service_digest)
        .context("service not exist")?
        .clone();

    tracing::debug!(service = %service.name(), "service found by digest");

    let nonce = generate_nonce();
    tracing::debug!(
        nonce = %RedactedNonce(nonce),
        "server generated nonce for handshake"
    );

    Ok(ControlHandshake {
        service,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quichole_shr::crypto::compute_auth_digest;
    use quichole_shr::protocol::service_digest;
    use quichole_shr::protocol::Hello::ControlChannelHello;
    use quichole_shr::protocol::Hello::DataChannelHello;

    fn build_server() -> ServerState {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"

            [services.dns]
            bind_addr = "0.0.0.0:5353"
            type = "udp"
        "#;

        let config: quichole_shr::config::ServerConfig = toml::from_str(toml_str).unwrap();
        ServerState::from_config(config).unwrap()
    }

    #[test]
    fn test_control_handshake_success() {
        let server = build_server();
        let digest = service_digest("ssh");
        let hello = ControlChannelHello {
            version: PROTO_V1,
            service_digest: digest,
        };
        let handshake = begin_control_handshake(&server, &hello).unwrap();
        let auth = Auth {
            digest: compute_auth_digest("default_secret", handshake.nonce()),
        };
        let mut session = handshake.verify_auth(&auth).unwrap();

        let (cmd, session_key) = session.create_data_channel();
        assert_eq!(cmd, ControlChannelCmd::CreateDataChannel);

        let data_hello = DataChannelHello {
            version: PROTO_V1,
            session_key,
        };
        let data_cmd = session.accept_data_channel_hello(&data_hello).unwrap();
        assert_eq!(data_cmd, DataChannelCmd::StartForwardTcp);
    }

    #[test]
    fn test_control_handshake_version_mismatch() {
        let server = build_server();
        let digest = service_digest("ssh");
        let hello = ControlChannelHello {
            version: PROTO_V1 + 1,
            service_digest: digest,
        };

        let result = begin_control_handshake(&server, &hello);
        assert!(result.is_err());
    }

    #[test]
    fn test_control_handshake_service_not_exist() {
        let server = build_server();
        let digest = service_digest("unknown");
        let hello = ControlChannelHello {
            version: PROTO_V1,
            service_digest: digest,
        };

        let result = begin_control_handshake(&server, &hello);
        assert!(result.is_err());
    }

    #[test]
    fn test_control_handshake_auth_failed() {
        let server = build_server();
        let digest = service_digest("ssh");
        let hello = ControlChannelHello {
            version: PROTO_V1,
            service_digest: digest,
        };
        let handshake = begin_control_handshake(&server, &hello).unwrap();
        let auth = Auth {
            digest: compute_auth_digest("wrong_token", handshake.nonce()),
        };

        let result = handshake.verify_auth(&auth);
        assert!(result.is_err());
    }

    #[test]
    fn test_data_channel_udp_flow() {
        let server = build_server();
        let digest = service_digest("dns");
        let hello = ControlChannelHello {
            version: PROTO_V1,
            service_digest: digest,
        };
        let handshake = begin_control_handshake(&server, &hello).unwrap();
        let auth = Auth {
            digest: compute_auth_digest("default_secret", handshake.nonce()),
        };
        let mut session = handshake.verify_auth(&auth).unwrap();

        let (_, session_key) = session.create_data_channel();
        let data_hello = DataChannelHello {
            version: PROTO_V1,
            session_key,
        };
        let data_cmd = session.accept_data_channel_hello(&data_hello).unwrap();
        assert_eq!(data_cmd, DataChannelCmd::StartForwardUdp);
    }

    #[test]
    fn test_data_channel_unknown_session_key() {
        let server = build_server();
        let digest = service_digest("ssh");
        let hello = ControlChannelHello {
            version: PROTO_V1,
            service_digest: digest,
        };
        let handshake = begin_control_handshake(&server, &hello).unwrap();
        let auth = Auth {
            digest: compute_auth_digest("default_secret", handshake.nonce()),
        };
        let mut session = handshake.verify_auth(&auth).unwrap();

        let data_hello = DataChannelHello {
            version: PROTO_V1,
            session_key: [9u8; 32],
        };
        let result = session.accept_data_channel_hello(&data_hello);
        assert!(result.is_err());
    }

    #[test]
    fn test_data_channel_wrong_version() {
        let server = build_server();
        let digest = service_digest("ssh");
        let hello = ControlChannelHello {
            version: PROTO_V1,
            service_digest: digest,
        };
        let handshake = begin_control_handshake(&server, &hello).unwrap();
        let auth = Auth {
            digest: compute_auth_digest("default_secret", handshake.nonce()),
        };
        let mut session = handshake.verify_auth(&auth).unwrap();

        let (_, session_key) = session.create_data_channel();
        let data_hello = DataChannelHello {
            version: PROTO_V1 + 1,
            session_key,
        };
        let result = session.accept_data_channel_hello(&data_hello);
        assert!(result.is_err());
    }
}
