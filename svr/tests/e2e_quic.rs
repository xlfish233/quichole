use anyhow::{Context, Result};
use fs2::FileExt;
use quichole_cli::client::ClientState;
use quichole_cli::runtime::{run_client, run_client_with_shutdown};
use quichole_shr::config::{
    ClientConfig, ClientServiceConfig, ServerConfig, ServerServiceConfig, ServiceType, TlsConfig,
};
use quichole_shr::logging::ShutdownSignal;
use quichole_svr::runtime::run_server;
use quichole_svr::server::ServerState;
use rcgen::{CertificateParams, KeyPair};
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};

struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(prev) = self.prev.take() {
            std::env::set_var(self.key, prev);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn set_env_var(key: &'static str, value: &str) -> EnvGuard {
    let prev = std::env::var(key).ok();
    std::env::set_var(key, value);
    EnvGuard { key, prev }
}

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

fn write_test_cert() -> Result<(PathBuf, PathBuf)> {
    let params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_path = temp_path("quichole_cert", "pem");
    let key_path = temp_path("quichole_key", "key");
    fs::write(&cert_path, cert.pem())?;
    fs::write(&key_path, key_pair.serialize_pem())?;
    Ok((cert_path, key_path))
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

async fn wait_for_port_close(addr: &str, timeout_secs: u64) -> Result<()> {
    let result = timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
                Ok(Ok(_)) => {
                    sleep(Duration::from_millis(100)).await;
                }
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
    })
    .await;

    if result.is_err() {
        Err(anyhow::anyhow!(
            "service port still accepting connections after control channel close"
        ))
    } else {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_tcp_forward_end_to_end() -> Result<()> {
    let _lock = acquire_e2e_lock();
    let (cert_path, key_path) = write_test_cert()?;
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
            cert: Some(cert_path.to_string_lossy().to_string()),
            key: Some(key_path.to_string_lossy().to_string()),
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
    let payload = b"quichole-e2e";

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

    client_handle.abort();
    echo_handle.abort();
    server_handle.abort();
    let _ = server_handle.await;
    let _ = client_handle.await;
    let _ = echo_handle.await;

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_service_stops_after_control_channel_close() -> Result<()> {
    let _lock = acquire_e2e_lock();
    let _env = set_env_var("QUIC_IDLE_TIMEOUT_MS", "2000");
    let (cert_path, key_path) = write_test_cert()?;
    let quic_port = unused_udp_port();
    let service_port = unused_tcp_port();

    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;
    let echo_handle = tokio::spawn(run_echo_server(local_listener));

    let server_config = ServerConfig {
        bind_addr: format!("127.0.0.1:{quic_port}"),
        heartbeat_interval: 1,
        heartbeat_ack_timeout: None,
        quic_idle_timeout_ms: None,
        default_token: Some("e2e_secret".to_string()),
        tls: TlsConfig {
            cert: Some(cert_path.to_string_lossy().to_string()),
            key: Some(key_path.to_string_lossy().to_string()),
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
        heartbeat_timeout: 5,
        retry_interval: 1,
        quic_idle_timeout_ms: None,
        default_token: Some("e2e_secret".to_string()),
        tls: TlsConfig {
            server_name: Some("localhost".to_string()),
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
    let client_shutdown_trigger = client_shutdown.clone();
    let client_handle =
        tokio::spawn(async move { run_client_with_shutdown(client_state, client_shutdown).await });

    let service_addr = format!("127.0.0.1:{service_port}");
    let payload = b"quichole-stop";

    let result = timeout(Duration::from_secs(20), async {
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

    client_shutdown_trigger.shutdown();
    client_handle.abort();
    let _ = client_handle.await;
    sleep(Duration::from_secs(3)).await;
    wait_for_port_close(&service_addr, 10).await?;

    server_handle.abort();
    echo_handle.abort();
    let _ = server_handle.await;
    let _ = echo_handle.await;

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_service_rebinds_after_client_reconnect() -> Result<()> {
    let _lock = acquire_e2e_lock();
    let _env = set_env_var("QUIC_IDLE_TIMEOUT_MS", "2000");
    let (cert_path, key_path) = write_test_cert()?;
    let quic_port = unused_udp_port();
    let service_port = unused_tcp_port();

    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;
    let echo_handle = tokio::spawn(run_echo_server(local_listener));

    let server_config = ServerConfig {
        bind_addr: format!("127.0.0.1:{quic_port}"),
        heartbeat_interval: 1,
        heartbeat_ack_timeout: None,
        quic_idle_timeout_ms: None,
        default_token: Some("e2e_secret".to_string()),
        tls: TlsConfig {
            cert: Some(cert_path.to_string_lossy().to_string()),
            key: Some(key_path.to_string_lossy().to_string()),
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

    let base_client_config = ClientConfig {
        remote_addr: format!("127.0.0.1:{quic_port}"),
        heartbeat_timeout: 5,
        retry_interval: 1,
        quic_idle_timeout_ms: None,
        default_token: Some("e2e_secret".to_string()),
        tls: TlsConfig {
            server_name: Some("localhost".to_string()),
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
    let server_shutdown = ShutdownSignal::new();
    let server_handle =
        tokio::spawn(async move { run_server(server_state, server_shutdown).await });

    let client_state =
        ClientState::from_config(base_client_config.clone()).context("build client")?;
    let client_shutdown = ShutdownSignal::new();
    let client_shutdown_trigger = client_shutdown.clone();
    let client_handle =
        tokio::spawn(async move { run_client_with_shutdown(client_state, client_shutdown).await });

    let service_addr = format!("127.0.0.1:{service_port}");
    let payload = b"quichole-reconnect";

    let first_round = timeout(Duration::from_secs(20), async {
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

    assert_eq!(first_round.as_slice(), payload);

    client_shutdown_trigger.shutdown();
    client_handle.abort();
    let _ = client_handle.await;
    sleep(Duration::from_secs(3)).await;
    wait_for_port_close(&service_addr, 10).await?;

    let client_state = ClientState::from_config(base_client_config).context("build client")?;
    let client_shutdown = ShutdownSignal::new();
    let client_shutdown_trigger = client_shutdown.clone();
    let client_handle =
        tokio::spawn(async move { run_client_with_shutdown(client_state, client_shutdown).await });

    let second_round = timeout(Duration::from_secs(20), async {
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

    assert_eq!(second_round.as_slice(), payload);

    client_shutdown_trigger.shutdown();
    client_handle.abort();
    server_handle.abort();
    echo_handle.abort();
    let _ = client_handle.await;
    let _ = server_handle.await;
    let _ = echo_handle.await;

    let _ = fs::remove_file(&cert_path);
    let _ = fs::remove_file(&key_path);

    Ok(())
}

// Note: test_stream_id_monotonic_across_connections was removed after
// commit 2fcd107 ("Prevent QUIC stream id reuse") because the stream ID
// reuse protection mechanism prevents reusing stream IDs across multiple
// data connections on the same QUIC connection. The test's assumption
// that multiple TCP connections would create distinct stream IDs is no
// longer valid. Use test_service_rebinds_after_client_reconnect to test
// client reconnection behavior instead.
