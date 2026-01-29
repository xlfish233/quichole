use quichole_cli::client::ClientState;
use quichole_cli::handshake::{auth_message, control_hello, data_channel_hello, verify_ack};
use quichole_shr::protocol::{Ack, ControlChannelCmd, DataChannelCmd};
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
fn test_e2e_control_and_data_channel_tcp() {
    let server = build_server();
    let client = build_client();

    let service = client.service("ssh").unwrap();
    let hello = control_hello(service.name());
    let handshake = begin_control_handshake(&server, &hello).unwrap();
    let auth = auth_message(service.token(), handshake.nonce());
    let mut session = handshake.verify_auth(&auth).unwrap();

    let (cmd, session_key) = session.create_data_channel();
    assert_eq!(cmd, ControlChannelCmd::CreateDataChannel);
    verify_ack(&Ack::Ok).unwrap();

    let data_hello = data_channel_hello(session_key);
    let data_cmd = session.accept_data_channel_hello(&data_hello).unwrap();
    assert_eq!(data_cmd, DataChannelCmd::StartForwardTcp);
}

#[test]
fn test_e2e_control_and_data_channel_udp() {
    let server = build_server();
    let client = build_client();

    let service = client.service("dns").unwrap();
    let hello = control_hello(service.name());
    let handshake = begin_control_handshake(&server, &hello).unwrap();
    let auth = auth_message(service.token(), handshake.nonce());
    let mut session = handshake.verify_auth(&auth).unwrap();

    let (cmd, session_key) = session.create_data_channel();
    assert_eq!(cmd, ControlChannelCmd::CreateDataChannel);

    let data_hello = data_channel_hello(session_key);
    let data_cmd = session.accept_data_channel_hello(&data_hello).unwrap();
    assert_eq!(data_cmd, DataChannelCmd::StartForwardUdp);
}
