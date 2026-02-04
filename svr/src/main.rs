use anyhow::{Context, Result};
use clap::Parser;
use quichole_shr::config::ServerConfig;
use quichole_shr::logging::ShutdownSignal;
use std::fs;
use std::path::{Path, PathBuf};

use quichole_shr::crypto::compute_auth_digest;
use quichole_shr::protocol::{service_digest, Auth, Hello, PROTO_V1};
use quichole_svr::handshake::begin_control_handshake;
use quichole_svr::runtime::run_server;
use quichole_svr::server::ServerState;

use tokio::signal::ctrl_c;

#[cfg(unix)]
use tokio::signal::unix::{self, SignalKind};

#[derive(Parser, Debug)]
#[command(name = "quichole-server", version, about = "Quichole server")]
struct Args {
    /// 配置文件路径
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
}

fn load_config(path: &Path) -> Result<ServerConfig> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read server config: {}", path.display()))?;
    let mut config: ServerConfig =
        toml::from_str(&content).context("failed to parse server config toml")?;
    config
        .validate()
        .context("server config validation failed")?;
    Ok(config)
}

/// Wait for Ctrl+C or SIGTERM and return when received
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        ctrl_c().await.expect("failed to install Ctrl+C handler");
        tracing::info!("received Ctrl+C, initiating shutdown");
    };

    #[cfg(unix)]
    let terminate = async {
        let mut sig_term = unix::signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        sig_term.recv().await;
        tracing::info!("received SIGTERM, initiating shutdown");
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Phase 1: Minimal logging before config
    let _minimal_guard = quichole_shr::logging::init_minimal_logging();

    let args = Args::parse();
    let config = load_config(&args.config)?;

    // Phase 2: Full logging after config
    let (_log_guard, _reload_handle) = quichole_shr::logging::init_logging(&config.logging)
        .context("failed to initialize logging")?;

    let server = ServerState::from_config(config)?;
    let config_ref = server.config();
    tracing::info!(
        bind_addr = %config_ref.bind_addr,
        services = server.services_len(),
        "server initialized"
    );

    for name in config_ref.services.keys() {
        let digest = quichole_shr::protocol::service_digest(name);
        if server.service_by_digest(&digest).is_none() {
            tracing::warn!(service = %name, "service digest index missing");
        }
        if let Some(service) = server.service(name) {
            tracing::debug!(
                service = service.name(),
                bind_addr = service.bind_addr(),
                service_type = ?service.service_type(),
                token_len = service.token().len(),
                "service loaded"
            );
        }
    }

    #[cfg(debug_assertions)]
    debug_self_check(&server);

    // Create shutdown signal
    let shutdown = ShutdownSignal::new();
    let shutdown_trigger = shutdown.clone();

    // Spawn signal handler task
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        shutdown_trigger.shutdown();
    });

    run_server(server, shutdown).await
}

#[cfg(debug_assertions)]
fn debug_self_check(server: &ServerState) {
    let (name, _) = match server.config().services.iter().next() {
        Some(entry) => entry,
        None => return,
    };

    let digest = service_digest(name);
    let hello = Hello::ControlChannelHello {
        version: PROTO_V1,
        service_digest: digest,
    };

    let handshake = match begin_control_handshake(server, &hello) {
        Ok(handshake) => handshake,
        Err(err) => {
            tracing::warn!(error = %err, "debug handshake begin failed");
            return;
        }
    };

    let service = match server.service(name) {
        Some(service) => service,
        None => return,
    };

    let auth = Auth {
        digest: compute_auth_digest(service.token(), handshake.nonce()),
    };

    let mut session = match handshake.verify_auth(&auth) {
        Ok(session) => session,
        Err(err) => {
            tracing::warn!(error = %err, "debug handshake auth failed");
            return;
        }
    };

    let (_, session_key) = session.create_data_channel();
    let data_hello = Hello::DataChannelHello {
        version: PROTO_V1,
        session_key,
    };

    let data_cmd = match session.accept_data_channel_hello(&data_hello) {
        Ok(cmd) => cmd,
        Err(err) => {
            tracing::warn!(error = %err, "debug data channel handshake failed");
            return;
        }
    };

    tracing::debug!(?data_cmd, "debug handshake ok");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write_temp_file(prefix: &str, contents: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut path = std::env::temp_dir();
        path.push(format!("{}_{}.toml", prefix, nanos));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn test_load_config_applies_default_token() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let path = write_temp_file("quichole_server", toml_str);
        let config = load_config(&path).unwrap();
        fs::remove_file(&path).unwrap();

        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "default_secret");
    }

    #[test]
    fn test_load_config_missing_token_error() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let path = write_temp_file("quichole_server", toml_str);
        let result = load_config(&path);
        fs::remove_file(&path).unwrap();

        assert!(result.is_err());
    }
}
