use anyhow::{bail, Context, Result};
use quichole_shr::config::ServiceType;
use quichole_shr::crypto::verify_auth_digest;
use quichole_shr::logging::{RedactedNonce, RedactedSessionKey};
use quichole_shr::protocol::{
    generate_nonce, generate_session_key, AuthResult, DataChannelCmd, DataChannelHelloV2, PROTO_V2,
};
use std::collections::HashMap;

use crate::server::ServerState;
use crate::service::Service;

pub struct ControlHandshake {
    service: Service,
    nonce: [u8; 32],
    conn_epoch: u64,
    hs_seq: u64,
}

impl ControlHandshake {
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub const fn conn_epoch(&self) -> u64 {
        self.conn_epoch
    }

    pub const fn hs_seq(&self) -> u64 {
        self.hs_seq
    }

    pub fn verify_auth(self, digest: &[u8; 32]) -> Result<ControlSession> {
        if !verify_auth_digest(digest, self.service.token(), &self.nonce) {
            bail!("auth failed");
        }

        Ok(ControlSession {
            service: self.service,
            conn_epoch: self.conn_epoch,
            data_channels: DataChannelManager::default(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DataChannelRequest {
    pub req_id: u64,
    pub session_key: [u8; 32],
    pub mode: DataChannelCmd,
}

#[derive(Default)]
struct DataChannelManager {
    pending: HashMap<u64, ([u8; 32], DataChannelCmd)>,
}

impl DataChannelManager {
    fn create_request(&mut self, req_id: u64, service_type: ServiceType) -> DataChannelRequest {
        let session_key = generate_session_key();
        tracing::debug!(
            session_key = %RedactedSessionKey(session_key),
            req_id,
            "server generated session key for data channel"
        );
        let mode = match service_type {
            ServiceType::Tcp => DataChannelCmd::StartForwardTcp,
            ServiceType::Udp => DataChannelCmd::StartForwardUdp,
        };
        self.pending.insert(req_id, (session_key, mode));
        DataChannelRequest {
            req_id,
            session_key,
            mode,
        }
    }

    fn accept_hello(
        &mut self,
        conn_epoch: u64,
        hello: &DataChannelHelloV2,
    ) -> Result<DataChannelCmd> {
        if hello.version != PROTO_V2 {
            bail!("protocol version mismatch");
        }

        if hello.conn_epoch != conn_epoch {
            bail!("conn epoch mismatch");
        }

        let (expected_key, mode) = self
            .pending
            .remove(&hello.req_id)
            .context("unknown req id")?;

        if expected_key != hello.session_key {
            bail!("session key mismatch");
        }

        Ok(mode)
    }
}

pub struct ControlSession {
    service: Service,
    conn_epoch: u64,
    data_channels: DataChannelManager,
}

impl ControlSession {
    pub fn service(&self) -> &Service {
        &self.service
    }

    pub const fn conn_epoch(&self) -> u64 {
        self.conn_epoch
    }

    pub fn create_data_channel(&mut self, req_id: u64) -> DataChannelRequest {
        self.data_channels
            .create_request(req_id, self.service.service_type())
    }

    pub fn accept_data_channel_hello(
        &mut self,
        hello: &DataChannelHelloV2,
    ) -> Result<DataChannelCmd> {
        self.data_channels.accept_hello(self.conn_epoch, hello)
    }
}

pub fn begin_control_handshake(
    server: &ServerState,
    service_digest: &[u8; 32],
    conn_epoch: u64,
    hs_seq: u64,
) -> Result<ControlHandshake> {
    tracing::debug!(
        service_digest = %format!("{:02x}***", service_digest[0]),
        conn_epoch,
        hs_seq,
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
        conn_epoch,
        hs_seq,
        "server generated nonce for handshake"
    );

    Ok(ControlHandshake {
        service,
        nonce,
        conn_epoch,
        hs_seq,
    })
}

pub fn auth_error_to_result(err: &anyhow::Error) -> AuthResult {
    if err.to_string().contains("service not exist") {
        AuthResult::ServiceNotExist
    } else {
        AuthResult::AuthFailed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quichole_shr::crypto::compute_auth_digest;
    use quichole_shr::protocol::service_digest;

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
        let handshake = begin_control_handshake(&server, &digest, 11, 1).unwrap();
        let auth_digest = compute_auth_digest("default_secret", handshake.nonce());
        let mut session = handshake.verify_auth(&auth_digest).unwrap();

        let req = session.create_data_channel(5);
        let data_hello = DataChannelHelloV2 {
            version: PROTO_V2,
            conn_epoch: 11,
            req_id: req.req_id,
            session_key: req.session_key,
        };
        let data_cmd = session.accept_data_channel_hello(&data_hello).unwrap();
        assert_eq!(data_cmd, DataChannelCmd::StartForwardTcp);
    }
}
