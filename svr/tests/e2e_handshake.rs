use quichole_cli::client::ClientState;
use quichole_cli::handshake::{
    client_auth, client_hello, data_channel_hello, verify_auth_result, ClientHandshakeContext,
};
use quichole_shr::protocol::{AuthResult, ControlFrame, DataChannelCmd, PROTO_V2};
use quichole_svr::handshake::begin_control_handshake;
use quichole_svr::server::ServerState;

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

fn build_client() -> ClientState {
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
    ClientState::from_config(config).unwrap()
}

#[test]
fn test_e2e_control_and_data_channel_tcp_v2() {
    let server = build_server();
    let client = build_client();

    let service = client.service("ssh").unwrap();
    let conn_epoch = 100_u64;
    let hs_seq = 1_u64;

    let hello = client_hello(service.name(), conn_epoch, hs_seq);
    let service_digest = match hello {
        ControlFrame::ClientHello {
            version,
            service_digest,
            conn_epoch: recv_epoch,
            hs_seq: recv_hs_seq,
        } => {
            assert_eq!(version, PROTO_V2);
            assert_eq!(recv_epoch, conn_epoch);
            assert_eq!(recv_hs_seq, hs_seq);
            service_digest
        }
        _ => panic!("unexpected hello frame"),
    };

    let handshake = begin_control_handshake(&server, &service_digest, conn_epoch, hs_seq).unwrap();
    let auth = client_auth(
        service.token(),
        handshake.nonce(),
        &ClientHandshakeContext { conn_epoch, hs_seq },
    );

    let digest = match auth {
        ControlFrame::ClientAuth {
            conn_epoch: recv_epoch,
            hs_seq: recv_hs_seq,
            digest,
        } => {
            assert_eq!(recv_epoch, conn_epoch);
            assert_eq!(recv_hs_seq, hs_seq);
            digest
        }
        _ => panic!("unexpected auth frame"),
    };

    let mut session = handshake.verify_auth(&digest).unwrap();
    verify_auth_result(&AuthResult::Ok).unwrap();

    let req = session.create_data_channel(7);
    assert_eq!(req.mode, DataChannelCmd::StartForwardTcp);

    let data_hello = data_channel_hello(conn_epoch, req.req_id, req.session_key);
    let data_cmd = session.accept_data_channel_hello(&data_hello).unwrap();
    assert_eq!(data_cmd, DataChannelCmd::StartForwardTcp);
}

#[test]
fn test_e2e_control_and_data_channel_udp_v2() {
    let server = build_server();
    let client = build_client();

    let service = client.service("dns").unwrap();
    let conn_epoch = 200_u64;
    let hs_seq = 1_u64;

    let hello = client_hello(service.name(), conn_epoch, hs_seq);
    let service_digest = match hello {
        ControlFrame::ClientHello { service_digest, .. } => service_digest,
        _ => panic!("unexpected hello frame"),
    };

    let handshake = begin_control_handshake(&server, &service_digest, conn_epoch, hs_seq).unwrap();
    let auth = client_auth(
        service.token(),
        handshake.nonce(),
        &ClientHandshakeContext { conn_epoch, hs_seq },
    );

    let digest = match auth {
        ControlFrame::ClientAuth { digest, .. } => digest,
        _ => panic!("unexpected auth frame"),
    };

    let mut session = handshake.verify_auth(&digest).unwrap();

    let req = session.create_data_channel(8);
    assert_eq!(req.mode, DataChannelCmd::StartForwardUdp);

    let data_hello = data_channel_hello(conn_epoch, req.req_id, req.session_key);
    let data_cmd = session.accept_data_channel_hello(&data_hello).unwrap();
    assert_eq!(data_cmd, DataChannelCmd::StartForwardUdp);
}
