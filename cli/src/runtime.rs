use anyhow::{anyhow, bail, Context, Result};
use boring::ssl::{SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};
use bytes::Bytes;
use quichole_shr::config::TlsConfig;
use quichole_shr::logging::{RedactedNonce, ShutdownSignal};
use quichole_shr::protocol::{encode_message, FrameDecoder};
use quichole_shr::protocol::{Ack, ControlChannelCmd, DataChannelCmd, UdpTraffic, PROTO_V1};
use quichole_shr::quic::{ConnectionRole, QuicApp, QuicConnectionState, QuicStreamHandle};
use serde::{de::DeserializeOwned, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};
use tokio_quiche::quic::{connect_with_config, ConnectionHook};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
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
    validate_client_tls_config(tls)?;
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
    let cert = tls.cert.as_deref().filter(|val| !val.is_empty());
    let key = tls.key.as_deref().filter(|val| !val.is_empty());
    let tls_cert = match (cert, key) {
        (Some(cert), Some(key)) => Some(TlsCertificatePaths {
            cert,
            private_key: key,
            kind: CertificateKind::X509,
        }),
        _ => None,
    };
    let mut settings = QuicSettings::default();
    if let Some(timeout_ms) = quic_idle_timeout_ms {
        settings.max_idle_timeout = Some(StdDuration::from_millis(timeout_ms));
    }
    settings.verify_peer = tls.verify_peer;
    let hooks = build_client_hooks(tls, tls_cert.is_some())?;
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

    send_framed(&control_stream, &hello).await?;
    tracing::debug!("hello sent, waiting for nonce");
    let nonce: [u8; 32] = recv_framed(&mut control_stream, &mut control_decoder).await?;
    tracing::debug!(
        nonce = %RedactedNonce(nonce),
        "nonce received from server, sending auth"
    );
    let auth = auth_message(service.token(), &nonce);
    tracing::debug!("auth message computed from token and nonce");
    send_framed(&control_stream, &auth).await?;
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
        match cmd {
            ControlChannelCmd::Heartbeat => {
                if let Err(err) = send_framed(&control_stream, &ControlChannelCmd::Heartbeat).await
                {
                    tracing::warn!(error = %err, "control channel heartbeat ack failed");
                    return Err(err);
                }
                continue;
            }
            ControlChannelCmd::CreateDataChannel => {
                tracing::debug!("received create data channel");
                let session_key: [u8; 32] =
                    recv_framed(&mut control_stream, &mut control_decoder).await?;
                let stream_id = conn_state.next_data_stream_id()?;
                let mut data_stream = manager.open_stream(stream_id).await?;
                tracing::debug!(stream_id, "data stream opened");
                let data_hello = data_channel_hello(session_key);
                if let Err(err) = send_framed(&data_stream, &data_hello).await {
                    tracing::warn!(error = %err, stream_id, "send data channel hello failed");
                    return Err(err);
                }
                let mut data_decoder = FrameDecoder::new();
                let data_cmd: DataChannelCmd =
                    match recv_framed(&mut data_stream, &mut data_decoder).await {
                        Ok(cmd) => cmd,
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                stream_id,
                                "receive data channel cmd failed"
                            );
                            return Err(err);
                        }
                    };
                tracing::debug!(mode = ?data_cmd, "data channel accepted");
                let pending = data_decoder.take_remaining();
                let pending = if pending.is_empty() {
                    None
                } else {
                    Some(pending.freeze())
                };

                let local_addr = service.local_addr().to_string();
                match data_cmd {
                    DataChannelCmd::StartForwardTcp => {
                        tokio::spawn(async move {
                            if let Err(err) = forward_tcp(&local_addr, data_stream, pending).await {
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
        }
    }
}

struct ClientTlsHook {
    ca: Option<String>,
    verify_peer: bool,
}

impl ConnectionHook for ClientTlsHook {
    fn create_custom_ssl_context_builder(
        &self,
        settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        if settings.kind != CertificateKind::X509 {
            return None;
        }
        let mut builder = SslContextBuilder::new(SslMethod::tls()).ok()?;
        if let Err(err) = builder.set_certificate_chain_file(settings.cert) {
            tracing::warn!(error = %err, "failed to load client certificate");
            return None;
        }
        if let Err(err) = builder.set_private_key_file(settings.private_key, SslFiletype::PEM) {
            tracing::warn!(error = %err, "failed to load client private key");
            return None;
        }
        if let Err(err) = builder.check_private_key() {
            tracing::warn!(error = %err, "client private key mismatch");
            return None;
        }
        if let Some(ca) = &self.ca {
            if let Err(err) = builder.set_ca_file(ca) {
                tracing::warn!(error = %err, "failed to load client CA file");
                return None;
            }
        }
        if self.verify_peer {
            builder.set_verify(SslVerifyMode::PEER);
        }
        Some(builder)
    }
}

fn build_client_hooks(tls: &TlsConfig, has_tls_cert: bool) -> Result<Hooks> {
    let ca = tls.ca.as_deref().filter(|val| !val.is_empty());
    if ca.is_none() {
        return Ok(Hooks::default());
    }
    if !has_tls_cert {
        bail!("tls.ca requires tls.cert and tls.key for client mTLS");
    }
    let hook = ClientTlsHook {
        ca: ca.map(str::to_string),
        verify_peer: tls.verify_peer,
    };
    Ok(Hooks {
        connection_hook: Some(Arc::new(hook)),
    })
}

fn validate_client_tls_config(tls: &TlsConfig) -> Result<()> {
    let cert = tls.cert.as_deref().filter(|val| !val.is_empty());
    let key = tls.key.as_deref().filter(|val| !val.is_empty());
    let ca = tls.ca.as_deref().filter(|val| !val.is_empty());
    if cert.is_some() ^ key.is_some() {
        bail!("tls.cert and tls.key must be set together");
    }
    if ca.is_some() && cert.is_none() {
        bail!("tls.ca requires tls.cert and tls.key for client mTLS");
    }
    Ok(())
}

async fn forward_tcp(
    local_addr: &str,
    stream: QuicStreamHandle,
    pending: Option<Bytes>,
) -> Result<()> {
    let stream_id = stream.id();
    tracing::debug!(local_addr, stream_id, "tcp forward start");
    let socket = TcpStream::connect(local_addr)
        .await
        .with_context(|| format!("connect local tcp {}", local_addr))?;
    let (quic_tx, mut quic_rx) = stream.split();
    let (mut reader, mut writer) = socket.into_split();

    let to_quic = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            tracing::debug!(local_addr, stream_id, bytes = n, "local->quic read");
            if n == 0 {
                quic_tx.send_fin().await?;
                break;
            }
            quic_tx.send(Bytes::copy_from_slice(&buf[..n])).await?;
            tracing::debug!(local_addr, stream_id, bytes = n, "local->quic sent");
        }
        Result::<()>::Ok(())
    };

    let from_quic = async {
        if let Some(pending) = pending {
            tracing::debug!(
                local_addr,
                stream_id,
                bytes = pending.len(),
                "quic->local pending"
            );
            writer.write_all(&pending).await?;
        }
        while let Some(chunk) = quic_rx.recv().await {
            if !chunk.data.is_empty() {
                tracing::debug!(
                    local_addr,
                    stream_id,
                    bytes = chunk.data.len(),
                    "quic->local recv"
                );
                writer.write_all(&chunk.data).await?;
            }
            if chunk.fin {
                tracing::debug!(local_addr, stream_id, "quic->local fin");
                writer.shutdown().await?;
                break;
            }
        }
        Result::<()>::Ok(())
    };

    tokio::try_join!(to_quic, from_quic)?;
    tracing::debug!(local_addr, stream_id, "tcp forward finished");
    Ok(())
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

async fn send_framed<T>(stream: &QuicStreamHandle, msg: &T) -> Result<()>
where
    T: Serialize,
{
    let frame = encode_message(msg)?;
    tracing::debug!(
        stream_id = stream.id(),
        len = frame.len(),
        "sending framed message"
    );
    stream.send(Bytes::from(frame)).await
}

async fn recv_framed<T>(stream: &mut QuicStreamHandle, decoder: &mut FrameDecoder) -> Result<T>
where
    T: DeserializeOwned,
{
    tracing::debug!(stream_id = stream.id(), "recv_framed: starting");
    loop {
        if let Some(result) = decoder.decode_next::<T>() {
            tracing::debug!(
                stream_id = stream.id(),
                "received framed message from decoder cache"
            );
            return result;
        }
        tracing::trace!(stream_id = stream.id(), "recv_framed: waiting for chunk");
        let chunk = stream
            .recv()
            .await
            .ok_or_else(|| anyhow!("quic stream closed"))?;
        tracing::debug!(
            stream_id = stream.id(),
            bytes = chunk.data.len(),
            fin = chunk.fin,
            "recv_framed: received chunk"
        );
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
    fn test_client_tls_requires_cert_key_when_ca_set() {
        let tls = TlsConfig {
            ca: Some("ca.pem".to_string()),
            ..TlsConfig::default()
        };

        let err = validate_client_tls_config(&tls).unwrap_err();
        assert!(err.to_string().contains("tls.ca requires"));
    }

    #[test]
    fn test_client_tls_requires_cert_key_pair() {
        let tls = TlsConfig {
            cert: Some("client.pem".to_string()),
            ..TlsConfig::default()
        };

        let err = validate_client_tls_config(&tls).unwrap_err();
        assert!(err.to_string().contains("tls.cert and tls.key"));
    }
}
