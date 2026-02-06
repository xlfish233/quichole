use anyhow::{anyhow, Result};
use bytes::Bytes;
use quichole_shr::config::TlsConfig;
use quichole_shr::logging::{RedactedNonce, ShutdownSignal};
use quichole_shr::protocol::{encode_message, FrameDecoder};
use quichole_shr::protocol::{Ack, ControlChannelCmd, DataChannelCmd, UdpTraffic, PROTO_V1};
use quichole_shr::quic::{
    build_client_tls_hooks, forward_tcp_bidirectional, recv_framed, send_framed, ConnectionRole,
    QuicApp, QuicConnectionState, QuicStreamHandle, QuicStreamManager,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::settings::{CertificateKind, QuicSettings, TlsCertificatePaths};
use tokio_quiche::socket::Socket;
use tokio_quiche::ConnectionParams;

use crate::client::ClientState;
use crate::handshake::{auth_message, control_hello, data_channel_hello, verify_ack};
use crate::service::ClientService;

pub async fn run_client(client: ClientState, shutdown: ShutdownSignal) -> Result<()> {
    run_client_with_shutdown(client, shutdown).await
}

pub async fn run_client_with_shutdown(client: ClientState, shutdown: ShutdownSignal) -> Result<()> {
    let client = Arc::new(client);
    let mut join_set = JoinSet::new();
    let mut shutdown_rx = shutdown.subscribe();

    for name in client.config().services.keys() {
        let service = client
            .service(name)
            .ok_or_else(|| anyhow!("service {} not found", name))?
            .clone();
        let remote_addr = client.config().remote_addr.clone();
        let tls = client.config().tls.clone();
        let retry = service
            .retry_interval()
            .unwrap_or(client.config().retry_interval);
        let quic_idle_timeout_ms = client.config().quic_idle_timeout_ms;
        let service_shutdown = shutdown.clone();

        join_set.spawn(async move {
            if let Err(err) = run_service_with_shutdown(
                remote_addr,
                tls,
                service,
                retry,
                quic_idle_timeout_ms,
                service_shutdown,
            )
            .await
            {
                tracing::warn!(error = %err, "client service stopped");
            }
        });
    }

    tokio::select! {
        _ = async {
            while join_set.join_next().await.is_some() {}
        } => Ok(()),
        _ = shutdown_rx.recv() => {
            tracing::info!("client shutdown signal received");
            join_set.abort_all();
            while join_set.join_next().await.is_some() {}
            Ok(())
        }
    }
}

async fn run_service_with_shutdown(
    remote_addr: String,
    tls: TlsConfig,
    service: ClientService,
    retry_interval: u64,
    quic_idle_timeout_ms: Option<u64>,
    shutdown: ShutdownSignal,
) -> Result<()> {
    loop {
        let mut shutdown_rx = shutdown.subscribe();
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!(service = service.name(), "service shutdown requested");
                return Ok(());
            }
            result = run_service_once(&remote_addr, &tls, &service, quic_idle_timeout_ms) => {
                match result {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            service = service.name(),
                            retry_interval,
                            "service connection failed, retrying"
                        );
                        sleep(Duration::from_secs(retry_interval)).await;
                    }
                }
            }
        }
    }
}

async fn run_service_once(
    remote_addr: &str,
    tls: &TlsConfig,
    service: &ClientService,
    quic_idle_timeout_ms: Option<u64>,
) -> Result<()> {
    let (tls_cert_key, ca) = tls.client_params()?;
    let remote = resolve_remote_addr(remote_addr).await?;
    let server_name = tls
        .server_name
        .clone()
        .or_else(|| extract_server_name(remote_addr))
        .unwrap_or_else(|| "localhost".to_string());

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(remote).await?;
    let socket: Socket<Arc<UdpSocket>, Arc<UdpSocket>> =
        Socket::<Arc<UdpSocket>, Arc<UdpSocket>>::from_udp(udp)?;
    let tls_cert = tls_cert_key
        .as_ref()
        .map(|(cert, key)| TlsCertificatePaths {
            cert,
            private_key: key,
            kind: CertificateKind::X509,
        });
    let mut settings = QuicSettings::default();
    if let Some(timeout_ms) = quic_idle_timeout_ms {
        settings.max_idle_timeout = Some(StdDuration::from_millis(timeout_ms));
    }
    settings.verify_peer = tls.verify_peer;

    let hooks = build_client_tls_hooks(ca, tls.verify_peer)?;
    let params = ConnectionParams::new_client(settings, tls_cert, hooks);

    let (app, handle) = QuicApp::new(quichole_shr::quic::CONTROL_STREAM_ID);
    let _conn = connect_with_config(socket, Some(server_name.as_str()), &params, app)
        .await
        .map_err(|err| anyhow!(err))?;
    tracing::debug!("quic connected");

    let (mut control_stream, manager) = handle.split();
    let mut control_decoder = FrameDecoder::new();

    let hello = control_hello(service.name());
    if hello.version() != PROTO_V1 {
        return Err(anyhow!("protocol version mismatch"));
    }

    send_framed(&control_stream, &hello, false).await?;
    tracing::debug!("hello sent, waiting for nonce");
    let nonce: [u8; 32] = recv_framed(&mut control_stream, &mut control_decoder).await?;
    tracing::debug!(
        nonce = %RedactedNonce(nonce),
        "nonce received from server, sending auth"
    );
    let auth = auth_message(service.token(), &nonce);
    tracing::debug!("auth message computed from token and nonce");
    send_framed(&control_stream, &auth, false).await?;
    tracing::debug!("auth sent, yielding multiple times");
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    tracing::debug!("waiting for ack");
    let ack: Ack = recv_framed(&mut control_stream, &mut control_decoder).await?;
    verify_ack(&ack)?;
    tracing::debug!("control handshake completed");

    let mut conn_state = QuicConnectionState::new(ConnectionRole::Client);

    loop {
        let cmd: ControlChannelCmd =
            match recv_framed(&mut control_stream, &mut control_decoder).await {
                Ok(cmd) => cmd,
                Err(err) => {
                    tracing::warn!(error = %err, "control channel read failed");
                    return Err(err);
                }
            };
        handle_control_command(
            cmd,
            &mut control_stream,
            &mut control_decoder,
            &manager,
            &mut conn_state,
            service,
        )
        .await?;
    }
}

async fn handle_control_command(
    cmd: ControlChannelCmd,
    control_stream: &mut QuicStreamHandle,
    control_decoder: &mut FrameDecoder,
    manager: &QuicStreamManager,
    conn_state: &mut QuicConnectionState,
    service: &ClientService,
) -> Result<()> {
    match cmd {
        ControlChannelCmd::Heartbeat => {
            if let Err(err) =
                send_framed(control_stream, &ControlChannelCmd::Heartbeat, false).await
            {
                tracing::warn!(error = %err, "control channel heartbeat ack failed");
                return Err(err);
            }
            Ok(())
        }
        ControlChannelCmd::CreateDataChannel => {
            tracing::debug!("received create data channel");
            let session_key: [u8; 32] = recv_framed(control_stream, control_decoder).await?;
            let stream_id = conn_state.next_data_stream_id()?;
            let mut data_stream = manager.open_stream(stream_id).await?;
            tracing::debug!(stream_id, "data stream opened");

            let data_hello = data_channel_hello(session_key);
            if let Err(err) = send_framed(&data_stream, &data_hello, false).await {
                tracing::warn!(error = %err, stream_id, "send data channel hello failed");
                return Err(err);
            }

            let mut data_decoder = FrameDecoder::new();
            let data_cmd: DataChannelCmd =
                match recv_framed(&mut data_stream, &mut data_decoder).await {
                    Ok(cmd) => cmd,
                    Err(err) => {
                        tracing::warn!(error = %err, stream_id, "receive data channel cmd failed");
                        return Err(err);
                    }
                };
            tracing::debug!(mode = ?data_cmd, "data channel accepted");

            spawn_data_forward_task(
                data_cmd,
                service.local_addr().to_string(),
                data_stream,
                pending_from_decoder(&mut data_decoder),
            );

            Ok(())
        }
    }
}

fn pending_from_decoder(decoder: &mut FrameDecoder) -> Option<Bytes> {
    let pending = decoder.take_remaining();
    if pending.is_empty() {
        None
    } else {
        Some(pending.freeze())
    }
}

fn spawn_data_forward_task(
    data_cmd: DataChannelCmd,
    local_addr: String,
    data_stream: QuicStreamHandle,
    pending: Option<Bytes>,
) {
    match data_cmd {
        DataChannelCmd::StartForwardTcp => {
            tokio::spawn(async move {
                let socket = match TcpStream::connect(&local_addr).await {
                    Ok(s) => s,
                    Err(err) => {
                        tracing::warn!(error = %err, local_addr, "failed to connect to local tcp service");
                        return;
                    }
                };

                if let Err(err) = forward_tcp_bidirectional(
                    socket,
                    data_stream,
                    pending,
                    format!("local={}", local_addr),
                )
                .await
                {
                    tracing::warn!(error = %err, "tcp forward failed");
                }
            });
        }
        DataChannelCmd::StartForwardUdp => {
            tokio::spawn(async move {
                if let Err(err) = forward_udp(&local_addr, data_stream, pending).await {
                    tracing::warn!(error = %err, "udp forward failed");
                }
            });
        }
    }
}

async fn forward_udp(
    local_addr: &str,
    stream: QuicStreamHandle,
    pending: Option<Bytes>,
) -> Result<()> {
    let stream_id = stream.id();
    let local_addr = local_addr.to_string();
    tracing::debug!(local_addr = %local_addr, stream_id, "udp forward start");
    let local = resolve_remote_addr(&local_addr).await?;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let (tx, mut rx) = stream.split();

    let udp = socket.clone();
    let local_addr_task = local_addr.clone();
    let mut recv_task = tokio::spawn(async move {
        let mut decoder = FrameDecoder::new();
        if let Some(pending) = pending {
            tracing::debug!(
                local_addr = %local_addr_task,
                stream_id,
                bytes = pending.len(),
                "quic->udp pending"
            );
            decoder.push(&pending);
            while let Some(result) = decoder.decode_next::<UdpTraffic>() {
                match result {
                    Ok(traffic) => {
                        let _ = udp.send_to(&traffic.data, local).await;
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        while let Some(chunk) = rx.recv().await {
            decoder.push(&chunk.data);
            while let Some(result) = decoder.decode_next::<UdpTraffic>() {
                match result {
                    Ok(traffic) => {
                        let _ = udp.send_to(&traffic.data, local).await;
                    }
                    Err(err) => return Err(err),
                }
            }
            if chunk.fin {
                break;
            }
        }
        Result::<()>::Ok(())
    });

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            res = &mut recv_task => {
                res??;
                break;
            }
            recv = socket.recv_from(&mut buf) => {
                let (n, from) = recv?;
                let traffic = UdpTraffic {
                    from,
                    data: Bytes::copy_from_slice(&buf[..n]),
                };
                let frame = encode_message(&traffic)?;
                tx.send(Bytes::from(frame)).await?;
            }
        }
    }

    Ok(())
}

async fn resolve_remote_addr(addr: &str) -> Result<SocketAddr> {
    if let Ok(parsed) = addr.parse() {
        return Ok(parsed);
    }
    let mut addrs = tokio::net::lookup_host(addr).await?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("failed to resolve {}", addr))
}

fn extract_server_name(addr: &str) -> Option<String> {
    if addr.starts_with('[') {
        let end = addr.find(']')?;
        return Some(addr[1..end].to_string());
    }
    addr.rsplit_once(':').map(|(host, _)| host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_tls_requires_cert_key_when_ca_set() {
        let tls = TlsConfig {
            ca: Some("ca.pem".to_string()),
            ..TlsConfig::default()
        };

        let err = tls.validate_client().unwrap_err();
        assert!(err.to_string().contains("tls.ca requires"));
    }

    #[test]
    fn test_client_tls_requires_cert_key_pair() {
        let tls = TlsConfig {
            cert: Some("client.pem".to_string()),
            ..TlsConfig::default()
        };

        let err = tls.validate_client().unwrap_err();
        assert!(err.to_string().contains("tls.cert and tls.key"));
    }
}
