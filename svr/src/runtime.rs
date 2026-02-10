use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use quichole_shr::config::{ServiceType, TlsConfig};
use quichole_shr::logging::ShutdownSignal;
use quichole_shr::protocol::{
    encode_message, AuthResult, ControlFrame, DataChannelCmd, DataChannelHelloV2, FrameDecoder,
    UdpTraffic,
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
use tokio::time::{interval, timeout, Duration, Instant, MissedTickBehavior};
use tokio_quiche::metrics::{DefaultMetrics, Metrics};
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::settings::{CertificateKind, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{listen, ConnectionParams};

use crate::handshake::{
    auth_error_to_result, begin_control_handshake, ControlSession, DataChannelRequest,
};
use crate::server::ServerState;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(800);
const HANDSHAKE_MAX_RETRY: u32 = 2;
const DATA_CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct ControlContext {
    conn_epoch: u64,
    hs_seq: u64,
    tick: u64,
    next_req_id: u64,
}

impl ControlContext {
    fn new(conn_epoch: u64) -> Self {
        Self {
            conn_epoch,
            hs_seq: 1,
            tick: 0,
            next_req_id: 1,
        }
    }

    fn next_req_id(&mut self) -> u64 {
        let req_id = self.next_req_id;
        self.next_req_id = self.next_req_id.saturating_add(1);
        req_id
    }

    fn validate_epoch(&self, incoming_epoch: u64) -> bool {
        incoming_epoch == self.conn_epoch
    }
}

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
    let mut conn_id = 0_u64;

    loop {
        tokio::select! {
            conn_result = listener.next() => {
                match conn_result {
                    Some(Ok(conn)) => {
                        conn_id = conn_id.saturating_add(1);
                        let server = server.clone();
                        let shutdown = shutdown.clone();
                        let this_conn_id = conn_id;
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(server, conn, shutdown, this_conn_id).await {
                                tracing::warn!(error = %err, conn_id = this_conn_id, "quic connection ended");
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
    tls.validate_server()?;

    let cert = tls.cert.as_deref().unwrap();
    let key = tls.key.as_deref().unwrap();
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
    settings.max_ack_delay = 100;

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

struct PendingDataRequest {
    request: DataChannelRequest,
    response: oneshot::Sender<Result<PreparedDataStream>>,
    created_at: Instant,
}

struct DataChannelHelloEvent {
    stream: QuicStreamHandle,
    hello: Result<DataChannelHelloV2>,
}

async fn handle_connection<M>(
    server: Arc<ServerState>,
    conn: tokio_quiche::InitialQuicConnection<tokio::net::UdpSocket, M>,
    shutdown: ShutdownSignal,
    conn_id: u64,
) -> Result<()>
where
    M: Metrics,
{
    let (app, handle) = QuicApp::new(quichole_shr::quic::CONTROL_STREAM_ID);
    let _conn = conn.start(app);
    tracing::debug!(conn_id, "quic connection started");

    let (mut control_stream, manager) = handle.split();
    let mut control_decoder = FrameDecoder::new();
    let mut control_ctx = ControlContext::new(0);

    let session = server_handshake(
        &server,
        &mut control_stream,
        &mut control_decoder,
        &mut control_ctx,
    )
    .await?;

    let service = session.service().clone();
    let (req_tx, req_rx) = mpsc::channel(64);
    let heartbeat_interval = server.config().heartbeat_interval;
    let heartbeat_ack_timeout = server
        .config()
        .heartbeat_ack_timeout
        .unwrap_or_else(|| heartbeat_interval.saturating_mul(3).max(3));

    let shutdown_for_control = shutdown.clone();
    let shutdown_for_service = shutdown.clone();

    tokio::spawn(async move {
        if let Err(err) = control_task_with_shutdown(
            session,
            control_ctx,
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

async fn server_handshake(
    server: &ServerState,
    control_stream: &mut QuicStreamHandle,
    control_decoder: &mut FrameDecoder,
    control_ctx: &mut ControlContext,
) -> Result<ControlSession> {
    for retry in 0..=HANDSHAKE_MAX_RETRY {
        let frame = timeout(
            HANDSHAKE_TIMEOUT,
            recv_framed::<ControlFrame>(control_stream, control_decoder),
        )
        .await
        .context("timeout waiting client hello")??;

        let (version, service_digest, conn_epoch, hs_seq) = match frame {
            ControlFrame::ClientHello {
                version,
                service_digest,
                conn_epoch,
                hs_seq,
            } => (version, service_digest, conn_epoch, hs_seq),
            other => {
                tracing::warn!(retry, frame = ?other, "unexpected control frame before handshake");
                continue;
            }
        };

        if version != quichole_shr::protocol::PROTO_V2 {
            tracing::warn!(retry, version, "protocol version mismatch");
            continue;
        }

        control_ctx.conn_epoch = conn_epoch;
        control_ctx.hs_seq = hs_seq;

        let handshake = match begin_control_handshake(server, &service_digest, conn_epoch, hs_seq) {
            Ok(handshake) => handshake,
            Err(err) => {
                let result = auth_error_to_result(&err);
                let auth_result = ControlFrame::ServerAuthResult {
                    conn_epoch,
                    hs_seq,
                    result,
                };
                send_framed(control_stream, &auth_result, false).await?;
                return Err(err);
            }
        };

        let challenge = ControlFrame::ServerChallenge {
            conn_epoch,
            hs_seq,
            nonce: *handshake.nonce(),
        };
        send_framed(control_stream, &challenge, false).await?;

        let auth_frame = timeout(
            HANDSHAKE_TIMEOUT,
            recv_framed::<ControlFrame>(control_stream, control_decoder),
        )
        .await
        .context("timeout waiting client auth")??;

        let digest = match auth_frame {
            ControlFrame::ClientAuth {
                conn_epoch: recv_epoch,
                hs_seq: recv_hs_seq,
                digest,
            } if recv_epoch == conn_epoch && recv_hs_seq == hs_seq => digest,
            other => {
                tracing::warn!(retry, frame = ?other, "unexpected client auth frame");
                continue;
            }
        };

        let session = match handshake.verify_auth(&digest) {
            Ok(session) => {
                let auth_result = ControlFrame::ServerAuthResult {
                    conn_epoch,
                    hs_seq,
                    result: AuthResult::Ok,
                };
                send_framed(control_stream, &auth_result, false).await?;
                session
            }
            Err(err) => {
                let auth_result = ControlFrame::ServerAuthResult {
                    conn_epoch,
                    hs_seq,
                    result: AuthResult::AuthFailed,
                };
                send_framed(control_stream, &auth_result, false).await?;
                return Err(err);
            }
        };

        let ready = ControlFrame::ControlReady { conn_epoch };
        send_framed(control_stream, &ready, false).await?;
        return Ok(session);
    }

    Err(anyhow!("server handshake failed after retries"))
}

async fn control_task_with_shutdown(
    mut session: ControlSession,
    mut control_ctx: ControlContext,
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
    let mut pending_requests: HashMap<u64, PendingDataRequest> = HashMap::new();
    let (hello_tx, mut hello_rx) = mpsc::channel::<DataChannelHelloEvent>(128);
    let mut cleanup_tick = interval(Duration::from_millis(200));
    cleanup_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                control_ctx.tick = control_ctx.tick.saturating_add(1);
                let heartbeat = ControlFrame::Heartbeat {
                    conn_epoch: control_ctx.conn_epoch,
                    tick: control_ctx.tick,
                };
                send_framed(&control_stream, &heartbeat, false).await?;
                if last_heartbeat.elapsed() > heartbeat_timeout {
                    return Err(anyhow!("control heartbeat timeout"));
                }
            }
            frame = recv_framed::<ControlFrame>(&mut control_stream, &mut control_decoder) => {
                let frame = frame?;
                if let Some(epoch) = frame.conn_epoch() {
                    if !control_ctx.validate_epoch(epoch) {
                        tracing::warn!(expected = control_ctx.conn_epoch, got = epoch, "drop stale frame in control task");
                        continue;
                    }
                }

                match frame {
                    ControlFrame::Heartbeat { tick, .. } => {
                        if tick >= control_ctx.tick {
                            last_heartbeat = Instant::now();
                        }
                    }
                    ControlFrame::OpenDataChannelResp {
                        conn_epoch: _,
                        req_id,
                        accepted,
                        error,
                    } => {
                        if !accepted {
                            tracing::warn!(req_id, error = ?error, "client rejected data channel request");
                        }
                    }
                    other => {
                        tracing::warn!(frame = ?other, "unexpected control frame from client");
                    }
                }
            }
            accepted = manager.accept_stream() => {
                let Some(data_stream) = accepted else {
                    break;
                };

                let hello_tx = hello_tx.clone();
                tokio::spawn(async move {
                    let event = recv_data_channel_hello(data_stream).await;
                    let _ = hello_tx.send(event).await;
                });
            }
            hello_event = hello_rx.recv() => {
                let Some(hello_event) = hello_event else {
                    break;
                };

                if let Err(err) = prepare_data_stream(
                    hello_event,
                    &mut session,
                    control_ctx.conn_epoch,
                    &mut pending_requests,
                ) {
                    tracing::warn!(error = %err, "failed to prepare data stream");
                }
            }
            request = req_rx.recv() => {
                let Some(request) = request else {
                    break;
                };

                let req_id = control_ctx.next_req_id();
                let req = session.create_data_channel(req_id);
                let mode = req.mode;
                let open_req = ControlFrame::OpenDataChannelReq {
                    conn_epoch: control_ctx.conn_epoch,
                    req_id: req.req_id,
                    session_key: req.session_key,
                    mode,
                };
                send_framed(&control_stream, &open_req, false).await?;

                pending_requests.insert(
                    req.req_id,
                    PendingDataRequest {
                        request: req,
                        response: request.response,
                        created_at: Instant::now(),
                    },
                );
            }
            _ = cleanup_tick.tick() => {
                timeout_pending_data_requests(&mut pending_requests);
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("shutdown signal received in control task");
                break;
            }
        }
    }

    for (_, pending) in pending_requests.drain() {
        let _ = pending
            .response
            .send(Err(anyhow!("control channel closed")));
    }

    Ok(())
}

async fn recv_data_channel_hello(mut data_stream: QuicStreamHandle) -> DataChannelHelloEvent {
    let stream_id = data_stream.id();
    tracing::debug!(stream_id, "data stream accepted");

    let mut data_decoder = FrameDecoder::new();
    let hello = async {
        let hello: DataChannelHelloV2 = timeout(
            DATA_CHANNEL_OPEN_TIMEOUT,
            recv_framed(&mut data_stream, &mut data_decoder),
        )
        .await
        .context("timeout waiting data channel hello")??;
        Ok::<DataChannelHelloV2, anyhow::Error>(hello)
    }
    .await;

    DataChannelHelloEvent {
        stream: data_stream,
        hello,
    }
}

fn prepare_data_stream(
    hello_event: DataChannelHelloEvent,
    session: &mut ControlSession,
    conn_epoch: u64,
    pending_requests: &mut HashMap<u64, PendingDataRequest>,
) -> Result<()> {
    let DataChannelHelloEvent { stream, hello } = hello_event;
    let stream_id = stream.id();
    let hello = hello?;

    let Some(pending) = pending_requests.remove(&hello.req_id) else {
        return Err(anyhow!("unknown req id {}", hello.req_id));
    };

    if hello.conn_epoch != conn_epoch {
        let _ = pending
            .response
            .send(Err(anyhow!("data channel conn epoch mismatch")));
        return Err(anyhow!("data channel conn epoch mismatch"));
    }

    if hello.req_id != pending.request.req_id {
        let _ = pending
            .response
            .send(Err(anyhow!("data channel req id mismatch")));
        return Err(anyhow!("data channel req id mismatch"));
    }

    let mode = session.accept_data_channel_hello(&hello)?;
    let _ = pending
        .response
        .send(Ok(PreparedDataStream { stream, mode }));
    tracing::debug!(stream_id, req_id = hello.req_id, "data stream prepared");
    Ok(())
}

fn timeout_pending_data_requests(pending_requests: &mut HashMap<u64, PendingDataRequest>) {
    let now = Instant::now();
    let timeout_reqs: Vec<u64> = pending_requests
        .iter()
        .filter_map(|(&req_id, pending)| {
            if now.duration_since(pending.created_at) >= DATA_CHANNEL_OPEN_TIMEOUT {
                Some(req_id)
            } else {
                None
            }
        })
        .collect();

    for req_id in timeout_reqs {
        if let Some(pending) = pending_requests.remove(&req_id) {
            let _ = pending
                .response
                .send(Err(anyhow!("data stream open timeout")));
        }
    }
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
                    spawn_udp_to_visitor(peer, socket.clone(), rx)?;
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
