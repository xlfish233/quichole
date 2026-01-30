use anyhow::{anyhow, bail, Context, Result};
use boring::ssl::{SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};
use boring::x509::X509;
use bytes::Bytes;
use futures_util::StreamExt;
use quichole_shr::config::{ServiceType, TlsConfig};
use quichole_shr::protocol::{encode_message, FrameDecoder};
use quichole_shr::protocol::{
    Ack, Auth, ControlChannelCmd, DataChannelCmd, Hello, UdpTraffic, PROTO_V1,
};
use quichole_shr::quic::{
    QuicApp, QuicStreamHandle, QuicStreamManager, QuicStreamReceiver, QuicStreamSender,
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration as StdDuration;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, Duration, Instant, MissedTickBehavior};
use tokio_quiche::metrics::{DefaultMetrics, Metrics};
use tokio_quiche::quic::{ConnectionHook, SimpleConnectionIdGenerator};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{listen, ConnectionParams};

use crate::handshake::begin_control_handshake;
use crate::server::ServerState;

pub async fn run_server(server: ServerState) -> Result<()> {
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

    while let Some(conn) = listener.next().await {
        let conn = conn?;
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(server, conn).await {
                tracing::warn!(error = %err, "quic connection ended");
            }
        });
    }

    Ok(())
}

fn build_server_params(tls: &TlsConfig) -> Result<ConnectionParams<'_>> {
    let cert = tls
        .cert
        .as_deref()
        .filter(|val| !val.is_empty())
        .ok_or_else(|| anyhow!("tls.cert is required for server"))?;
    let key = tls
        .key
        .as_deref()
        .filter(|val| !val.is_empty())
        .ok_or_else(|| anyhow!("tls.key is required for server"))?;
    let ca = tls
        .ca
        .as_deref()
        .filter(|val| !val.is_empty())
        .map(str::to_string);
    if tls.require_client_cert && ca.is_none() {
        bail!("tls.ca is required when require_client_cert = true");
    }

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
    let hooks = build_server_hooks(ca, tls.require_client_cert)?;
    Ok(ConnectionParams::new_server(settings, tls_paths, hooks))
}

struct ServerTlsHook {
    ca: Option<String>,
    require_client_cert: bool,
}

impl ConnectionHook for ServerTlsHook {
    fn create_custom_ssl_context_builder(
        &self,
        settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        if settings.kind != CertificateKind::X509 {
            return None;
        }
        let mut builder = SslContextBuilder::new(SslMethod::tls()).ok()?;
        if let Err(err) = builder.set_certificate_chain_file(settings.cert) {
            tracing::warn!(error = %err, "failed to load server certificate");
            return None;
        }
        if let Err(err) = builder.set_private_key_file(settings.private_key, SslFiletype::PEM) {
            tracing::warn!(error = %err, "failed to load server private key");
            return None;
        }
        if let Err(err) = builder.check_private_key() {
            tracing::warn!(error = %err, "server private key mismatch");
            return None;
        }
        if let Some(ca) = &self.ca {
            if let Err(err) = builder.set_ca_file(ca) {
                tracing::warn!(error = %err, "failed to load server CA file");
                return None;
            }
            if let Ok(pem) = std::fs::read(ca) {
                if let Ok(certs) = X509::stack_from_pem(&pem) {
                    for cert in certs {
                        let _ = builder.add_client_ca(&cert);
                    }
                }
            }
        }
        if self.require_client_cert {
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
        Some(builder)
    }
}

fn build_server_hooks(ca: Option<String>, require_client_cert: bool) -> Result<Hooks> {
    if ca.is_none() && !require_client_cert {
        return Ok(Hooks::default());
    }
    let hook = ServerTlsHook {
        ca,
        require_client_cert,
    };
    Ok(Hooks {
        connection_hook: Some(Arc::new(hook)),
    })
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
    send_framed(&control_stream, handshake.nonce()).await?;
    tracing::debug!("nonce sent, yielding multiple times");
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    tracing::debug!("receiving auth");

    let auth: Auth = recv_framed(&mut control_stream, &mut control_decoder).await?;
    let session = match handshake.verify_auth(&auth) {
        Ok(session) => {
            send_framed(&control_stream, &Ack::Ok).await?;
            tracing::debug!("control handshake completed");
            session
        }
        Err(err) => {
            send_framed(&control_stream, &Ack::AuthFailed).await?;
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

    tokio::spawn(async move {
        if let Err(err) =
            control_task(
                session,
                control_stream,
                manager,
                req_rx,
                heartbeat_interval,
                heartbeat_ack_timeout,
            )
            .await
        {
            tracing::warn!(error = %err, "control task failed");
        }
    });

    match service.service_type() {
        ServiceType::Tcp => run_tcp_service(service.bind_addr().to_string(), req_tx).await?,
        ServiceType::Udp => run_udp_service(service.bind_addr().to_string(), req_tx).await?,
    }

    Ok(())
}

async fn control_task(
    mut session: crate::handshake::ControlSession,
    mut control_stream: QuicStreamHandle,
    mut manager: QuicStreamManager,
    mut req_rx: mpsc::Receiver<ControlRequest>,
    heartbeat_interval: u64,
    heartbeat_ack_timeout: u64,
) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(heartbeat_interval));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let heartbeat_timeout = Duration::from_secs(heartbeat_ack_timeout.max(1));
    let mut last_heartbeat = Instant::now();
    let mut control_decoder = FrameDecoder::new();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Keep the QUIC connection alive and give clients a liveness signal.
                // Client currently ignores the payload but reading it resets its idle timer.
                send_framed(&control_stream, &ControlChannelCmd::Heartbeat).await?;
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
                send_framed(&control_stream, &cmd).await?;
                send_framed(&control_stream, &session_key).await?;

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
                send_framed(&data_stream, &data_cmd).await?;
                tracing::debug!(mode = ?data_cmd, "data channel ready");

                let _ = request.response.send(Ok(PreparedDataStream {
                    stream: data_stream,
                    mode: data_cmd,
                }));
            }
        }
    }

    Ok(())
}

async fn run_tcp_service(bind_addr: String, req_tx: mpsc::Sender<ControlRequest>) -> Result<()> {
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("bind tcp {}", bind_addr))?;
    tracing::info!(bind_addr = %bind_addr, "tcp service listening");

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
        DataChannelCmd::StartForwardTcp => forward_tcp(socket, prepared.stream, peer).await,
        DataChannelCmd::StartForwardUdp => Err(anyhow!("unexpected udp data channel for tcp")),
    }
}

async fn run_udp_service(bind_addr: String, req_tx: mpsc::Sender<ControlRequest>) -> Result<()> {
    let socket = UdpSocket::bind(&bind_addr)
        .await
        .with_context(|| format!("bind udp {}", bind_addr))?;
    tracing::info!(bind_addr = %bind_addr, "udp service listening");

    let socket = Arc::new(socket);
    let mut sessions: HashMap<SocketAddr, UdpSession> = HashMap::new();
    let mut buf = vec![0u8; 64 * 1024];

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

async fn forward_tcp(socket: TcpStream, stream: QuicStreamHandle, peer: SocketAddr) -> Result<()> {
    let stream_id = stream.id();
    tracing::debug!(peer = %peer, stream_id, "tcp forwarding started");
    let (quic_tx, mut quic_rx) = stream.split();
    let (mut reader, mut writer) = socket.into_split();

    let to_quic = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            tracing::debug!(peer = %peer, stream_id, bytes = n, "tcp->quic read");
            if n == 0 {
                quic_tx.send_fin().await?;
                break;
            }
            quic_tx.send(Bytes::copy_from_slice(&buf[..n])).await?;
            tracing::debug!(peer = %peer, stream_id, bytes = n, "tcp->quic sent");
        }
        Result::<()>::Ok(())
    };

    let from_quic = async {
        while let Some(chunk) = quic_rx.recv().await {
            if !chunk.data.is_empty() {
                tracing::debug!(
                    peer = %peer,
                    stream_id,
                    bytes = chunk.data.len(),
                    "quic->tcp recv"
                );
                writer.write_all(&chunk.data).await?;
            }
            if chunk.fin {
                tracing::debug!(peer = %peer, stream_id, "quic->tcp fin");
                writer.shutdown().await?;
                break;
            }
        }
        Result::<()>::Ok(())
    };

    tokio::try_join!(to_quic, from_quic)?;
    tracing::debug!(peer = %peer, "tcp forwarding finished");
    Ok(())
}

async fn send_framed<T>(stream: &QuicStreamHandle, msg: &T) -> Result<()>
where
    T: Serialize,
{
    let frame = encode_message(msg)?;
    tracing::debug!(stream_id = stream.id(), len = frame.len(), "sending framed message");
    stream.send(Bytes::from(frame)).await?;
    
    // 确保数据有机会被发送到网络
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    
    Ok(())
}

async fn recv_framed<T>(stream: &mut QuicStreamHandle, decoder: &mut FrameDecoder) -> Result<T>
where
    T: DeserializeOwned,
{
    tracing::debug!(stream_id = stream.id(), "recv_framed: starting");
    loop {
        if let Some(result) = decoder.decode_next::<T>() {
            tracing::debug!(stream_id = stream.id(), "received framed message from decoder cache");
            return result;
        }
        tracing::trace!(stream_id = stream.id(), "recv_framed: waiting for chunk");
        let chunk = stream
            .recv()
            .await
            .ok_or_else(|| anyhow!("quic stream closed"))?;
        tracing::debug!(stream_id = stream.id(), bytes = chunk.data.len(), fin = chunk.fin, "recv_framed: received chunk");
        decoder.push(&chunk.data);
        if chunk.fin {
            if let Some(result) = decoder.decode_next::<T>() {
                return result;
            }
            return Err(anyhow!("quic stream finished before message complete"));
        }
    }
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
