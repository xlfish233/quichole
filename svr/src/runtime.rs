use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use quichole_shr::config::{ServiceType, TlsConfig};
use quichole_shr::logging::ShutdownSignal;
use quichole_shr::protocol::{encode_message, FrameDecoder};
use quichole_shr::protocol::{
    Ack, Auth, ControlChannelCmd, DataChannelCmd, Hello, UdpTraffic, PROTO_V1,
};
use quichole_shr::quic::{
    build_server_tls_hooks, forward_tcp_bidirectional, recv_framed, send_framed, QuicApp,
    QuicStreamHandle, QuicStreamManager, QuicStreamReceiver, QuicStreamSender,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration, Instant, MissedTickBehavior};
use tokio_quiche::metrics::{DefaultMetrics, Metrics};
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::settings::{CertificateKind, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{listen, ConnectionParams};

use crate::handshake::begin_control_handshake;
use crate::server::ServerState;

pub async fn run_server(server: ServerState, shutdown: ShutdownSignal) -> Result<()> {
    let server = Arc::new(server);
    let bind_addr = server.config().bind_addr.clone();
    let tls = server.config().tls.clone();

    let udp_socket = UdpSocket::bind(&bind_addr)
        .await
        .with_context(|| format!("bind quic udp socket {}", bind_addr))?;
    let params = build_server_params(&tls)?;
    let listeners = listen(
        [udp_socket],
        params,
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )?;
    let mut listener = listeners
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no quic listener created"))?;

    tracing::info!(bind_addr = %bind_addr, "quic listener started");

    let mut shutdown_rx = shutdown.subscribe();

    loop {
        tokio::select! {
            conn_result = listener.next() => {
                match conn_result {
                    Some(Ok(conn)) => {
                        let server = server.clone();
                        let shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(server, conn, shutdown).await {
                                tracing::warn!(error = %err, "quic connection ended");
                            }
                        });
                    }
                    Some(Err(err)) => {
                        tracing::warn!(error = %err, "quic connection failed");
                    }
                    None => {
                        tracing::info!("listener exhausted, stopping server");
                        break;
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("shutdown signal received, stopping server");
                break;
            }
        }
    }

    Ok(())
}

fn build_server_params(tls: &TlsConfig) -> Result<ConnectionParams<'_>> {
    // Validate configuration
    tls.validate_server()?;

    // Extract parameters - using as_deref() to keep them as &str in this scope
    let cert = tls.cert.as_deref().unwrap(); // safe after validation
    let key = tls.key.as_deref().unwrap(); // safe after validation
    let ca = tls
        .ca
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(str::to_string);

    let tls_paths = TlsCertificatePaths {
        cert,
        private_key: key,
        kind: CertificateKind::X509,
    };

    let mut settings = QuicSettings::default();
    if let Some(timeout_ms) = std::env::var("QUIC_IDLE_TIMEOUT_MS")
        .ok()
        .and_then(|val| val.parse::<u64>().ok())
    {
        settings.max_idle_timeout = Some(StdDuration::from_millis(timeout_ms));
    }

    let hooks = build_server_tls_hooks(ca, tls.require_client_cert)?;
    Ok(ConnectionParams::new_server(settings, tls_paths, hooks))
}

struct ControlRequest {
    response: oneshot::Sender<Result<PreparedDataStream>>,
}

struct PreparedDataStream {
    stream: QuicStreamHandle,
    mode: DataChannelCmd,
}

async fn handle_connection<M>(
    server: Arc<ServerState>,
    conn: tokio_quiche::InitialQuicConnection<tokio::net::UdpSocket, M>,
    shutdown: ShutdownSignal,
) -> Result<()>
where
    M: Metrics,
{
    let (app, handle) = QuicApp::new(quichole_shr::quic::CONTROL_STREAM_ID);
    let _conn = conn.start(app);
    tracing::debug!("quic connection started");

    let (mut control_stream, manager) = handle.split();
    let mut control_decoder = FrameDecoder::new();

    let hello: Hello = recv_framed(&mut control_stream, &mut control_decoder).await?;
    if hello.version() != PROTO_V1 {
        return Err(anyhow!("protocol version mismatch"));
    }

    tracing::debug!("beginning control handshake");
    let handshake = begin_control_handshake(&server, &hello)?;
    tracing::debug!("sending nonce");
    send_framed(&control_stream, handshake.nonce(), true).await?;
    tracing::debug!("nonce sent, yielding multiple times");
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    tracing::debug!("receiving auth");

    let auth: Auth = recv_framed(&mut control_stream, &mut control_decoder).await?;
    let session = match handshake.verify_auth(&auth) {
        Ok(session) => {
            send_framed(&control_stream, &Ack::Ok, true).await?;
            tracing::debug!("control handshake completed");
            session
        }
        Err(err) => {
            send_framed(&control_stream, &Ack::AuthFailed, true).await?;
            return Err(err);
        }
    };

    let service = session.service().clone();
    let (req_tx, req_rx) = mpsc::channel(64);
    let heartbeat_interval = server.config().heartbeat_interval;
    let heartbeat_ack_timeout = server
        .config()
        .heartbeat_ack_timeout
        .unwrap_or_else(|| heartbeat_interval.saturating_mul(3).max(3));

    // Clone shutdown for use in both tasks
    let shutdown_for_control = shutdown.clone();
    let shutdown_for_service = shutdown.clone();

    tokio::spawn(async move {
        if let Err(err) = control_task_with_shutdown(
            session,
            control_stream,
            manager,
            req_rx,
            heartbeat_interval,
            heartbeat_ack_timeout,
            shutdown_for_control,
        )
        .await
        {
            tracing::warn!(error = %err, "control task failed");
        }
    });

    match service.service_type() {
        ServiceType::Tcp => {
            run_tcp_service_with_shutdown(
                service.bind_addr().to_string(),
                req_tx,
                shutdown_for_service,
            )
            .await?
        }
        ServiceType::Udp => {
            run_udp_service_with_shutdown(
                service.bind_addr().to_string(),
                req_tx,
                shutdown_for_service,
            )
            .await?
        }
    }

    Ok(())
}

async fn control_task_with_shutdown(
    mut session: crate::handshake::ControlSession,
    mut control_stream: QuicStreamHandle,
    mut manager: QuicStreamManager,
    mut req_rx: mpsc::Receiver<ControlRequest>,
    heartbeat_interval: u64,
    heartbeat_ack_timeout: u64,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(heartbeat_interval));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let heartbeat_timeout = Duration::from_secs(heartbeat_ack_timeout.max(1));
    let mut last_heartbeat = Instant::now();
    let mut control_decoder = FrameDecoder::new();
    let mut shutdown_rx = shutdown.subscribe();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Keep the QUIC connection alive and give clients a liveness signal.
                // Client currently ignores the payload but reading it resets its idle timer.
                send_framed(&control_stream, &ControlChannelCmd::Heartbeat, true).await?;
                if last_heartbeat.elapsed() > heartbeat_timeout {
                    return Err(anyhow!("control heartbeat timeout"));
                }
            }
            cmd = recv_framed::<ControlChannelCmd>(&mut control_stream, &mut control_decoder) => {
                match cmd {
                    Ok(ControlChannelCmd::Heartbeat) => {
                        last_heartbeat = Instant::now();
                    }
                    Ok(other) => {
                        tracing::warn!(cmd = ?other, "unexpected control cmd from client");
                    }
                    Err(err) => {
                        return Err(err);
                    }
                }
            }
            request = req_rx.recv() => {
                let Some(request) = request else {
                    break;
                };

                tracing::debug!("requesting data channel");
                let (cmd, session_key) = session.create_data_channel();
                send_framed(&control_stream, &cmd, true).await?;
                send_framed(&control_stream, &session_key, true).await?;

                let mut data_stream = manager
                    .accept_stream()
                    .await
                    .ok_or_else(|| anyhow!("data stream closed"))?;
                let stream_id = data_stream.id();
                tracing::debug!(stream_id, "data stream accepted");
                let mut data_decoder = FrameDecoder::new();
                let hello: Hello = match recv_framed(&mut data_stream, &mut data_decoder).await {
                    Ok(hello) => hello,
                    Err(err) => {
                        tracing::warn!(error = %err, stream_id, "data channel hello failed");
                        return Err(err);
                    }
                };
                let data_cmd = session.accept_data_channel_hello(&hello)?;
                send_framed(&data_stream, &data_cmd, true).await?;
                tracing::debug!(mode = ?data_cmd, "data channel ready");

                let _ = request.response.send(Ok(PreparedDataStream {
                    stream: data_stream,
                    mode: data_cmd,
                }));
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("shutdown signal received in control task");
                break;
            }
        }
    }

    Ok(())
}

async fn run_tcp_service_with_shutdown(
    bind_addr: String,
    req_tx: mpsc::Sender<ControlRequest>,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("bind tcp {}", bind_addr))?;
    tracing::info!(bind_addr = %bind_addr, "tcp service listening");

    let mut shutdown_rx = shutdown.subscribe();

    loop {
        tokio::select! {
            _ = req_tx.closed() => {
                tracing::info!(bind_addr = %bind_addr, "control channel closed, stopping tcp service");
                break;
            }
            accept = listener.accept() => {
                let (socket, peer) = accept?;
                let req_tx = req_tx.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_tcp_connection(socket, peer, req_tx).await {
                        tracing::warn!(error = %err, "tcp forward failed");
                    }
                });
            }
            _ = shutdown_rx.recv() => {
                tracing::info!(bind_addr = %bind_addr, "shutdown signal received, stopping tcp service");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_tcp_connection(
    socket: TcpStream,
    peer: SocketAddr,
    req_tx: mpsc::Sender<ControlRequest>,
) -> Result<()> {
    tracing::debug!(peer = %peer, "tcp visitor connected");
    let prepared = request_data_stream(req_tx).await?;
    match prepared.mode {
        DataChannelCmd::StartForwardTcp => {
            forward_tcp_bidirectional(socket, prepared.stream, None, format!("peer={}", peer)).await
        }
        DataChannelCmd::StartForwardUdp => Err(anyhow!("unexpected udp data channel for tcp")),
    }
}

async fn run_udp_service_with_shutdown(
    bind_addr: String,
    req_tx: mpsc::Sender<ControlRequest>,
    shutdown: ShutdownSignal,
) -> Result<()> {
    let socket = UdpSocket::bind(&bind_addr)
        .await
        .with_context(|| format!("bind udp {}", bind_addr))?;
    tracing::info!(bind_addr = %bind_addr, "udp service listening");

    let socket = Arc::new(socket);
    let mut sessions: HashMap<SocketAddr, UdpSession> = HashMap::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut shutdown_rx = shutdown.subscribe();

    loop {
        tokio::select! {
            _ = req_tx.closed() => {
                tracing::info!(bind_addr = %bind_addr, "control channel closed, stopping udp service");
                break;
            }
            recv = socket.recv_from(&mut buf) => {
                let (n, peer) = recv?;
        let sender = if let Some(session) = sessions.get(&peer) {
            session.sender.clone()
        } else {
            let prepared = request_data_stream(req_tx.clone()).await?;
            if prepared.mode != DataChannelCmd::StartForwardUdp {
                tracing::warn!(mode = ?prepared.mode, "unexpected data channel mode for udp");
                continue;
            }
            let (tx, rx) = prepared.stream.split();
            let udp = socket.clone();
            spawn_udp_to_visitor(peer, udp.clone(), rx)?;
            sessions.insert(peer, UdpSession { sender: tx.clone() });
            tx
        };

        let traffic = UdpTraffic {
            from: peer,
            data: Bytes::copy_from_slice(&buf[..n]),
        };
        let frame = encode_message(&traffic)?;
        sender.send(Bytes::from(frame)).await?;
            }
            _ = shutdown_rx.recv() => {
                tracing::info!(bind_addr = %bind_addr, "shutdown signal received, stopping udp service");
                break;
            }
        }
    }

    Ok(())
}

struct UdpSession {
    sender: QuicStreamSender,
}

fn spawn_udp_to_visitor(
    visitor: SocketAddr,
    udp: Arc<UdpSocket>,
    mut receiver: QuicStreamReceiver,
) -> Result<()> {
    tokio::spawn(async move {
        let mut decoder = FrameDecoder::new();
        while let Some(chunk) = receiver.recv().await {
            decoder.push(&chunk.data);
            while let Some(result) = decoder.decode_next::<UdpTraffic>() {
                match result {
                    Ok(traffic) => {
                        let _ = udp.send_to(&traffic.data, visitor).await;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "udp traffic decode failed");
                        return;
                    }
                }
            }
            if chunk.fin {
                break;
            }
        }
    });
    Ok(())
}

async fn request_data_stream(req_tx: mpsc::Sender<ControlRequest>) -> Result<PreparedDataStream> {
    let (tx, rx) = oneshot::channel();
    req_tx
        .send(ControlRequest { response: tx })
        .await
        .map_err(|_| anyhow!("control channel closed"))?;
    rx.await.map_err(|_| anyhow!("control channel closed"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_params_requires_ca_for_mtls() {
        let tls = TlsConfig {
            cert: Some("server.pem".to_string()),
            key: Some("server.key".to_string()),
            require_client_cert: true,
            ..TlsConfig::default()
        };

        let err = build_server_params(&tls).unwrap_err();
        assert!(err.to_string().contains("tls.ca is required"));
    }
}
