use anyhow::{bail, Result};
use quichole_shr::crypto::compute_auth_digest;
use quichole_shr::protocol::{Ack, Auth, Hello, PROTO_V1};

pub fn control_hello(service_name: &str) -> Hello {
    Hello::ControlChannelHello {
        version: PROTO_V1,
        service_digest: quichole_shr::protocol::service_digest(service_name),
    }
}

pub fn auth_message(token: &str, nonce: &[u8; 32]) -> Auth {
    Auth {
        digest: compute_auth_digest(token, nonce),
    }
}

pub fn data_channel_hello(session_key: [u8; 32]) -> Hello {
    Hello::DataChannelHello {
        version: PROTO_V1,
        session_key,
    }
}

pub fn verify_ack(ack: &Ack) -> Result<()> {
    match ack {
        Ack::Ok => Ok(()),
        Ack::ServiceNotExist => bail!("service not exist"),
        Ack::AuthFailed => bail!("auth failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quichole_shr::protocol::{service_digest, Hello::ControlChannelHello};

    #[test]
    fn test_control_hello_builds_digest() {
        let hello = control_hello("ssh");
        let ControlChannelHello {
            version,
            service_digest: digest,
        } = hello
        else {
            panic!("unexpected hello type");
        };

        assert_eq!(version, PROTO_V1);
        assert_eq!(digest, service_digest("ssh"));
    }

    #[test]
    fn test_auth_message_digest() {
        let nonce = [1u8; 32];
        let auth = auth_message("token", &nonce);
        let expected = compute_auth_digest("token", &nonce);
        assert_eq!(auth.digest, expected);
    }

    #[test]
    fn test_data_channel_hello() {
        let session_key = [2u8; 32];
        let hello = data_channel_hello(session_key);
        match hello {
            Hello::DataChannelHello {
                version,
                session_key,
            } => {
                assert_eq!(version, PROTO_V1);
                assert_eq!(session_key, [2u8; 32]);
            }
            _ => panic!("unexpected hello type"),
        }
    }

    #[test]
    fn test_verify_ack() {
        assert!(verify_ack(&Ack::Ok).is_ok());
        assert!(verify_ack(&Ack::ServiceNotExist).is_err());
        assert!(verify_ack(&Ack::AuthFailed).is_err());
    }
}
