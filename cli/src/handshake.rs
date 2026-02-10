use anyhow::{bail, Result};
use quichole_shr::crypto::compute_auth_digest;
use quichole_shr::protocol::{
    service_digest, AuthResult, ControlFrame, DataChannelCmd, DataChannelHelloV2, PROTO_V2,
};

#[derive(Debug, Clone)]
pub struct ClientHandshakeContext {
    pub conn_epoch: u64,
    pub hs_seq: u64,
}

pub fn client_hello(service_name: &str, conn_epoch: u64, hs_seq: u64) -> ControlFrame {
    ControlFrame::ClientHello {
        version: PROTO_V2,
        service_digest: service_digest(service_name),
        conn_epoch,
        hs_seq,
    }
}

pub fn client_auth(token: &str, nonce: &[u8; 32], ctx: &ClientHandshakeContext) -> ControlFrame {
    ControlFrame::ClientAuth {
        conn_epoch: ctx.conn_epoch,
        hs_seq: ctx.hs_seq,
        digest: compute_auth_digest(token, nonce),
    }
}

pub fn verify_auth_result(result: &AuthResult) -> Result<()> {
    match result {
        AuthResult::Ok => Ok(()),
        AuthResult::ServiceNotExist => bail!("service not exist"),
        AuthResult::AuthFailed => bail!("auth failed"),
    }
}

pub fn data_channel_hello(
    conn_epoch: u64,
    req_id: u64,
    session_key: [u8; 32],
) -> DataChannelHelloV2 {
    DataChannelHelloV2 {
        version: PROTO_V2,
        conn_epoch,
        req_id,
        session_key,
    }
}

pub fn build_data_channel_resp(
    conn_epoch: u64,
    req_id: u64,
    accepted: bool,
    error: Option<String>,
) -> ControlFrame {
    ControlFrame::OpenDataChannelResp {
        conn_epoch,
        req_id,
        accepted,
        error,
    }
}

pub fn map_mode(mode: DataChannelCmd) -> DataChannelCmd {
    mode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_v2() {
        let frame = client_hello("ssh", 7, 1);
        match frame {
            ControlFrame::ClientHello {
                version,
                conn_epoch,
                hs_seq,
                ..
            } => {
                assert_eq!(version, PROTO_V2);
                assert_eq!(conn_epoch, 7);
                assert_eq!(hs_seq, 1);
            }
            _ => panic!("unexpected frame"),
        }
    }

    #[test]
    fn test_verify_auth_result() {
        assert!(verify_auth_result(&AuthResult::Ok).is_ok());
        assert!(verify_auth_result(&AuthResult::ServiceNotExist).is_err());
        assert!(verify_auth_result(&AuthResult::AuthFailed).is_err());
    }
}
