use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use quichole_shr::config::TlsConfig;
use quichole_shr::logging::ShutdownSignal;
use quichole_shr::protocol::{
    encode_message, ControlFrame, DataChannelCmd, DataChannelHelloV2, FrameDecoder, UdpTraffic,
};
use quichole_shr::quic::{
    build_client_tls_hooks, forward_tcp_bidirectional, recv_framed, send_framed, ConnectionRole,
    QuicApp, QuicConnectionState, QuicStreamHandle, QuicStreamManager,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout, Duration};
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::settings::{CertificateKind, QuicSettings, TlsCertificatePaths};
use tokio_quiche::socket::Socket;
use tokio_quiche::ConnectionParams;

use crate::client::ClientState;
use crate::handshake::{
    build_data_channel_resp, client_auth, client_hello, data_channel_hello, map_mode,
    verify_auth_result, ClientHandshakeContext,
};
use crate::service::ClientService;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(800);
const HANDSHAKE_MAX_RETRY: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientControlState {
    Init,
    WaitChallenge,
    WaitAuthResult,
    WaitReady,
    Ready,
    Closed,
}

#[derive(Debug)]
struct ControlContext {
    conn_epoch: u64,
    hs_seq: u64,
    state: ClientControlState,
    conn_state: QuicConnectionState,
}

impl ControlContext {
    fn new(conn_epoch: u64) -> Self {
        Self {
            conn_epoch,
            hs_seq: 1,
            state: ClientControlState::Init,
            conn_state: QuicConnectionState::new(ConnectionRole::Client),
        }
    }

    fn handshake_ctx(&self) -> ClientHandshakeContext {
        ClientHandshakeContext {
            conn_epoch: self.conn_epoch,
            hs_seq: self.hs_seq,
        }
    }

    fn validate_epoch(&self, incoming_epoch: u64) -> bool {
        incoming_epoch == self.conn_epoch
    }
}

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
    let mut conn_epoch = 0_u64;
    loop {
        conn_epoch = conn_epoch.saturating_add(1);
        let mut shutdown_rx = shutdown.subscribe();
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!(service = service.name(), "service shutdown requested");
                return Ok(());
            }
            result = run_service_once(&remote_addr, &tls, &service, quic_idle_timeout_ms, conn_epoch) => {
                match result {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            service = service.name(),
                            retry_interval,
                            conn_epoch,
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
    conn_epoch: u64,
) -> Result<()> {
    let tls_params = tls.client_params()?;
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
    let tls_cert = tls_params
        .cert_key
        .as_ref()
        .map(|pair| TlsCertificatePaths {
            cert: &pair.cert,
            private_key: &pair.key,
            kind: CertificateKind::X509,
        });

    let mut settings = QuicSettings::default();
    settings.max_ack_delay = 100;
    if let Some(timeout_ms) = quic_idle_timeout_ms {
        settings.max_idle_timeout = Some(StdDuration::from_millis(timeout_ms));
    }
    settings.verify_peer = tls.verify_peer;

    let hooks = build_client_tls_hooks(tls_params.ca, tls.verify_peer)?;
    let params = ConnectionParams::new_client(settings, tls_cert, hooks);

    let (app, handle) = QuicApp::new(quichole_shr::quic::CONTROL_STREAM_ID);
    let _conn = connect_with_config(socket, Some(server_name.as_str()), &params, app)
        .await
        .map_err(|err| anyhow!(err))?;
    tracing::debug!(conn_epoch, "quic connected");

    let (mut control_stream, manager) = handle.split();
    let mut control_decoder = FrameDecoder::new();
    let mut control_ctx = ControlContext::new(conn_epoch);

    run_control_owner(
        &mut control_stream,
        &mut control_decoder,
        &manager,
        service,
        &mut control_ctx,
    )
    .await
}

async fn run_control_owner(
    control_stream: &mut QuicStreamHandle,
    control_decoder: &mut FrameDecoder,
    manager: &QuicStreamManager,
    service: &ClientService,
    control_ctx: &mut ControlContext,
) -> Result<()> {
    client_handshake(control_stream, control_decoder, service, control_ctx).await?;
    control_ctx.state = ClientControlState::Ready;

    loop {
        let frame: ControlFrame = recv_framed(control_stream, control_decoder).await?;
        if let Some(epoch) = frame.conn_epoch() {
            if !control_ctx.validate_epoch(epoch) {
                tracing::warn!(
                    expected = control_ctx.conn_epoch,
                    got = epoch,
                    "drop control frame from stale epoch"
                );
                continue;
            }
        }

        match frame {
            ControlFrame::Heartbeat { conn_epoch, tick } => {
                let ack = ControlFrame::Heartbeat { conn_epoch, tick };
                send_framed(control_stream, &ack, false).await?;
            }
            ControlFrame::OpenDataChannelReq {
                conn_epoch,
                req_id,
                session_key,
                mode,
            } => {
                let result = handle_data_channel_request(
                    manager,
                    service,
                    control_ctx,
                    conn_epoch,
                    req_id,
                    session_key,
                    mode,
                )
                .await;

                match result {
                    Ok(()) => {
                        let resp = build_data_channel_resp(conn_epoch, req_id, true, None);
                        send_framed(control_stream, &resp, false).await?;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, req_id, "data channel request failed");
                        let resp = build_data_channel_resp(
                            conn_epoch,
                            req_id,
                            false,
                            Some(err.to_string()),
                        );
                        send_framed(control_stream, &resp, false).await?;
                    }
                }
            }
            other => {
                tracing::warn!(frame = ?other, "unexpected control frame in ready state");
            }
        }
    }
}

async fn client_handshake(
    control_stream: &mut QuicStreamHandle,
    control_decoder: &mut FrameDecoder,
    service: &ClientService,
    control_ctx: &mut ControlContext,
) -> Result<()> {
    let hello = client_hello(service.name(), control_ctx.conn_epoch, control_ctx.hs_seq);

    for retry in 0..=HANDSHAKE_MAX_RETRY {
        control_ctx.state = ClientControlState::WaitChallenge;
        send_framed(control_stream, &hello, false).await?;

        let challenge = timeout(
            HANDSHAKE_TIMEOUT,
            recv_framed::<ControlFrame>(control_stream, control_decoder),
        )
        .await
        .context("timeout waiting server challenge")??;

        let nonce = match challenge {
            ControlFrame::ServerChallenge {
                conn_epoch,
                hs_seq,
                nonce,
            } if conn_epoch == control_ctx.conn_epoch && hs_seq == control_ctx.hs_seq => nonce,
            other => {
                tracing::warn!(retry, frame = ?other, "unexpected challenge frame");
                continue;
            }
        };

        control_ctx.state = ClientControlState::WaitAuthResult;
        let auth = client_auth(service.token(), &nonce, &control_ctx.handshake_ctx());
        send_framed(control_stream, &auth, false).await?;

        let auth_result = timeout(
            HANDSHAKE_TIMEOUT,
            recv_framed::<ControlFrame>(control_stream, control_decoder),
        )
        .await
        .context("timeout waiting auth result")??;

        let result = match auth_result {
            ControlFrame::ServerAuthResult {
                conn_epoch,
                hs_seq,
                result,
            } if conn_epoch == control_ctx.conn_epoch && hs_seq == control_ctx.hs_seq => result,
            other => {
                tracing::warn!(retry, frame = ?other, "unexpected auth result frame");
                continue;
            }
        };

        verify_auth_result(&result)?;

        control_ctx.state = ClientControlState::WaitReady;
        let ready = timeout(
            HANDSHAKE_TIMEOUT,
            recv_framed::<ControlFrame>(control_stream, control_decoder),
        )
        .await
        .context("timeout waiting control ready")??;

        match ready {
            ControlFrame::ControlReady { conn_epoch } if conn_epoch == control_ctx.conn_epoch => {
                return Ok(());
            }
            other => {
                tracing::warn!(retry, frame = ?other, "unexpected control ready frame");
                continue;
            }
        }
    }

    control_ctx.state = ClientControlState::Closed;
    Err(anyhow!("handshake failed after retries"))
}

async fn handle_data_channel_request(
    manager: &QuicStreamManager,
    service: &ClientService,
    control_ctx: &mut ControlContext,
    conn_epoch: u64,
    req_id: u64,
    session_key: [u8; 32],
    mode: DataChannelCmd,
) -> Result<()> {
    let stream_id = control_ctx.conn_state.next_data_stream_id()?;
    tracing::debug!(req_id, stream_id, mode = ?mode, "open data channel request received");
    let data_stream = manager.open_stream(stream_id).await?;

    let hello: DataChannelHelloV2 = data_channel_hello(conn_epoch, req_id, session_key);
    send_framed(&data_stream, &hello, false).await?;

    spawn_data_forward_task(
        map_mode(mode),
        service.local_addr().to_string(),
        data_stream,
        None,
    );

    Ok(())
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
