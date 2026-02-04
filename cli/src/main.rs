use anyhow::{Context, Result};
use clap::Parser;
use quichole_shr::config::ClientConfig;
use quichole_shr::logging::ShutdownSignal;
use std::fs;
use std::path::{Path, PathBuf};

use quichole_cli::client::ClientState;
use quichole_cli::handshake::{auth_message, control_hello, data_channel_hello, verify_ack};
use quichole_cli::runtime::run_client;
use quichole_shr::protocol::{generate_nonce, Ack};

use tokio::signal::ctrl_c;

#[cfg(unix)]
use tokio::signal::unix::{self, SignalKind};

#[derive(Parser, Debug)]
#[command(name = "quichole-client", version, about = "Quichole client")]
struct Args {
    /// 配置文件路径
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
}

fn load_config(path: &Path) -> Result<ClientConfig> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read client config: {}", path.display()))?;
    let mut config: ClientConfig =
        toml::from_str(&content).context("failed to parse client config toml")?;
    config
        .validate()
        .context("client config validation failed")?;
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

    let client = ClientState::from_config(config)?;
    let config_ref = client.config();
    tracing::info!(
        remote_addr = %config_ref.remote_addr,
        services = client.services_len(),
        "client initialized"
    );

    for name in config_ref.services.keys() {
        if let Some(service) = client.service(name) {
            tracing::debug!(
                service = service.name(),
                local_addr = service.local_addr(),
                service_type = ?service.service_type(),
                token_len = service.token().len(),
                retry_interval = ?service.retry_interval(),
                "service loaded"
            );
        }
    }

    #[cfg(debug_assertions)]
    debug_self_check(&client);

    // Create shutdown signal
    let shutdown = ShutdownSignal::new();
    let shutdown_trigger = shutdown.clone();

    // Spawn signal handler task
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        shutdown_trigger.shutdown();
    });

    run_client(client, shutdown).await
}

#[cfg(debug_assertions)]
fn debug_self_check(client: &ClientState) {
    let (name, _) = match client.config().services.iter().next() {
        Some(entry) => entry,
        None => return,
    };

    let service = match client.service(name) {
        Some(service) => service,
        None => return,
    };

    let hello = control_hello(name);
    let nonce = generate_nonce();
    let auth = auth_message(service.token(), &nonce);
    let _ = verify_ack(&Ack::Ok);
    let _ = data_channel_hello(nonce);

    tracing::debug!(
        service = service.name(),
        hello_version = hello.version(),
        auth_digest_prefix = format!("{:02x?}", &auth.digest[..4]),
        "debug client handshake ok"
    );
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
            remote_addr = "example.com:4433"
            default_token = "default_secret"

            [services.ssh]
            local_addr = "127.0.0.1:22"
        "#;

        let path = write_temp_file("quichole_client", toml_str);
        let config = load_config(&path).unwrap();
        fs::remove_file(&path).unwrap();

        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "default_secret");
    }

    #[test]
    fn test_load_config_missing_token_error() {
        let toml_str = r#"
            remote_addr = "example.com:4433"

            [services.ssh]
            local_addr = "127.0.0.1:22"
        "#;

        let path = write_temp_file("quichole_client", toml_str);
        let result = load_config(&path);
        fs::remove_file(&path).unwrap();

        assert!(result.is_err());
    }
}
