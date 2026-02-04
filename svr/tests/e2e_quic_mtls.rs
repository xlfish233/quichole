use anyhow::{Context, Result};
use fs2::FileExt;
use quichole_cli::client::ClientState;
use quichole_cli::runtime::run_client;
use quichole_shr::config::{
    ClientConfig, ClientServiceConfig, ServerConfig, ServerServiceConfig, ServiceType, TlsConfig,
};
use quichole_shr::logging::ShutdownSignal;
use quichole_svr::runtime::run_server;
use quichole_svr::server::ServerState;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};

fn temp_path(prefix: &str, suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!("{}_{}.{}", prefix, nanos, suffix));
    path
}

fn acquire_e2e_lock() -> fs::File {
    let path = std::env::temp_dir().join("quichole_e2e.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.lock_exclusive().unwrap();
    file
}

fn write_cert(path: &PathBuf, cert_pem: &str) -> Result<()> {
    fs::write(path, cert_pem)?;
    Ok(())
}

fn write_key(path: &PathBuf, key_pem: &str) -> Result<()> {
    fs::write(path, key_pem)?;
    Ok(())
}

fn build_ca() -> Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(Vec::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    Ok((cert, key_pair))
}

fn build_signed_cert(
    subject_alt_names: Vec<String>,
    usages: Vec<ExtendedKeyUsagePurpose>,
    ca: &Certificate,
    ca_key: &KeyPair,
) -> Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(subject_alt_names)?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = usages;
    let key_pair = KeyPair::generate()?;
    let cert = params.signed_by(&key_pair, ca, ca_key)?;
    Ok((cert, key_pair))
}

fn write_mtls_certs() -> Result<(PathBuf, PathBuf, PathBuf, PathBuf, PathBuf)> {
    let (ca_cert, ca_key) = build_ca()?;
    let (server_cert, server_key) = build_signed_cert(
        vec!["localhost".to_string()],
        vec![ExtendedKeyUsagePurpose::ServerAuth],
        &ca_cert,
        &ca_key,
    )?;
    let (client_cert, client_key) = build_signed_cert(
        vec!["client".to_string()],
        vec![ExtendedKeyUsagePurpose::ClientAuth],
        &ca_cert,
        &ca_key,
    )?;

    let ca_path = temp_path("quichole_ca", "pem");
    let server_cert_path = temp_path("quichole_server", "pem");
    let server_key_path = temp_path("quichole_server", "key");
    let client_cert_path = temp_path("quichole_client", "pem");
    let client_key_path = temp_path("quichole_client", "key");

    write_cert(&ca_path, &ca_cert.pem())?;
    write_cert(&server_cert_path, &server_cert.pem())?;
    write_key(&server_key_path, &server_key.serialize_pem())?;
    write_cert(&client_cert_path, &client_cert.pem())?;
    write_key(&client_key_path, &client_key.serialize_pem())?;

    Ok((
        ca_path,
        server_cert_path,
        server_key_path,
        client_cert_path,
        client_key_path,
    ))
}

fn unused_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

fn unused_tcp_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().port()
}

async fn run_echo_server(listener: TcpListener) {
    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if socket.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_tcp_forward_mtls_end_to_end() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    let _lock = acquire_e2e_lock();
    let (ca_path, server_cert_path, server_key_path, client_cert_path, client_key_path) =
        write_mtls_certs()?;
    let quic_port = unused_udp_port();
    let service_port = unused_tcp_port();

    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;
    let echo_handle = tokio::spawn(run_echo_server(local_listener));

    let server_config = ServerConfig {
        bind_addr: format!("127.0.0.1:{quic_port}"),
        heartbeat_interval: 30,
        heartbeat_ack_timeout: None,
        quic_idle_timeout_ms: None,
        default_token: Some("e2e_secret".to_string()),
        tls: TlsConfig {
            cert: Some(server_cert_path.to_string_lossy().to_string()),
            key: Some(server_key_path.to_string_lossy().to_string()),
            ca: Some(ca_path.to_string_lossy().to_string()),
            require_client_cert: true,
            ..TlsConfig::default()
        },
        services: HashMap::from([(
            "echo".to_string(),
            ServerServiceConfig {
                bind_addr: format!("127.0.0.1:{service_port}"),
                token: String::new(),
                service_type: ServiceType::Tcp,
            },
        )]),
        logging: Default::default(),
    };

    let client_config = ClientConfig {
        remote_addr: format!("127.0.0.1:{quic_port}"),
        heartbeat_timeout: 40,
        retry_interval: 1,
        quic_idle_timeout_ms: None,
        default_token: Some("e2e_secret".to_string()),
        tls: TlsConfig {
            server_name: Some("localhost".to_string()),
            ca: Some(ca_path.to_string_lossy().to_string()),
            verify_peer: true,
            cert: Some(client_cert_path.to_string_lossy().to_string()),
            key: Some(client_key_path.to_string_lossy().to_string()),
            ..TlsConfig::default()
        },
        services: HashMap::from([(
            "echo".to_string(),
            ClientServiceConfig {
                local_addr: local_addr.to_string(),
                token: String::new(),
                service_type: ServiceType::Tcp,
                retry_interval: None,
            },
        )]),
        logging: Default::default(),
    };

    let server_state = ServerState::from_config(server_config).context("build server state")?;
    let client_state = ClientState::from_config(client_config).context("build client state")?;

    let server_shutdown = ShutdownSignal::new();
    let server_handle =
        tokio::spawn(async move { run_server(server_state, server_shutdown).await });
    let client_shutdown = ShutdownSignal::new();
    let client_handle =
        tokio::spawn(async move { run_client(client_state, client_shutdown).await });

    let service_addr = format!("127.0.0.1:{service_port}");
    let payload = b"quichole-mtls-e2e";

    let result = timeout(Duration::from_secs(30), async {
        let mut stream = loop {
            match TcpStream::connect(&service_addr).await {
                Ok(stream) => break stream,
                Err(_) => {
                    sleep(Duration::from_millis(50)).await;
                }
            }
        };

        stream.write_all(payload).await?;
        let mut buf = vec![0u8; payload.len()];
        stream.read_exact(&mut buf).await?;
        Ok::<Vec<u8>, anyhow::Error>(buf)
    })
    .await??;

    assert_eq!(result.as_slice(), payload);

    server_handle.abort();
    client_handle.abort();
    echo_handle.abort();
    let _ = server_handle.await;
    let _ = client_handle.await;
    let _ = echo_handle.await;

    let _ = fs::remove_file(&ca_path);
    let _ = fs::remove_file(&server_cert_path);
    let _ = fs::remove_file(&server_key_path);
    let _ = fs::remove_file(&client_cert_path);
    let _ = fs::remove_file(&client_key_path);

    Ok(())
}
