use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use quichole_shr::config::TlsConfig;
use quichole_shr::protocol::{encode_message, FrameDecoder};
use quichole_shr::protocol::{Ack, ControlChannelCmd, DataChannelCmd, UdpTraffic, PROTO_V1};
use quichole_shr::quic::{ConnectionRole, QuicApp, QuicConnectionState, QuicStreamHandle};
use serde::{de::DeserializeOwned, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, Duration};
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::socket::Socket;
use tokio_quiche::ConnectionParams;

use crate::client::ClientState;
use crate::handshake::{auth_message, control_hello, data_channel_hello, verify_ack};
use crate::service::ClientService;

pub async fn run_client(client: ClientState) -> Result<()> {
    let client = Arc::new(client);
    let mut handles = Vec::new();

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
        handles.push(tokio::spawn(async move {
            if let Err(err) = run_service(remote_addr, tls, service, retry).await {
                tracing::warn!(error = %err, "client service stopped");
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}

async fn run_service(
    remote_addr: String,
    tls: TlsConfig,
    service: ClientService,
    retry_interval: u64,
) -> Result<()> {
    loop {
        match run_service_once(&remote_addr, &tls, &service).await {
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

async fn run_service_once(
    remote_addr: &str,
    tls: &TlsConfig,
    service: &ClientService,
) -> Result<()> {
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
    let tls_cert = match (&tls.cert, &tls.key) {
        (Some(cert), Some(key)) => Some(TlsCertificatePaths {
            cert,
            private_key: key,
            kind: CertificateKind::X509,
        }),
        _ => None,
    };
    let settings = QuicSettings::default();
    let hooks = Hooks::default();
    let params = ConnectionParams::new_client(settings, tls_cert, hooks);

    let (app, handle) = QuicApp::new(quichole_shr::quic::CONTROL_STREAM_ID);
    let _conn = connect_with_config(socket, Some(server_name.as_str()), &params, app)
        .await
        .map_err(|err| anyhow!(err))?;

    let (mut control_stream, manager) = handle.split();
    let mut control_decoder = FrameDecoder::new();

    let hello = control_hello(service.name());
    if hello.version() != PROTO_V1 {
        return Err(anyhow!("protocol version mismatch"));
    }

    send_framed(&control_stream, &hello).await?;
    let nonce: [u8; 32] = recv_framed(&mut control_stream, &mut control_decoder).await?;
    let auth = auth_message(service.token(), &nonce);
    send_framed(&control_stream, &auth).await?;
    let ack: Ack = recv_framed(&mut control_stream, &mut control_decoder).await?;
    verify_ack(&ack)?;

    let mut conn_state = QuicConnectionState::new(ConnectionRole::Client);

    loop {
        let cmd: ControlChannelCmd = recv_framed(&mut control_stream, &mut control_decoder).await?;
        match cmd {
            ControlChannelCmd::Heartbeat => continue,
            ControlChannelCmd::CreateDataChannel => {
                let session_key: [u8; 32] =
                    recv_framed(&mut control_stream, &mut control_decoder).await?;
                let stream_id = conn_state.next_data_stream_id()?;
                let mut data_stream = manager.open_stream(stream_id).await?;
                let data_hello = data_channel_hello(session_key);
                send_framed(&data_stream, &data_hello).await?;
                let mut data_decoder = FrameDecoder::new();
                let data_cmd: DataChannelCmd =
                    recv_framed(&mut data_stream, &mut data_decoder).await?;

                let local_addr = service.local_addr().to_string();
                match data_cmd {
                    DataChannelCmd::StartForwardTcp => {
                        tokio::spawn(async move {
                            if let Err(err) = forward_tcp(&local_addr, data_stream).await {
                                tracing::warn!(error = %err, "tcp forward failed");
                            }
                        });
                    }
                    DataChannelCmd::StartForwardUdp => {
                        tokio::spawn(async move {
                            if let Err(err) = forward_udp(&local_addr, data_stream).await {
                                tracing::warn!(error = %err, "udp forward failed");
                            }
                        });
                    }
                }
            }
        }
    }
}

async fn forward_tcp(local_addr: &str, stream: QuicStreamHandle) -> Result<()> {
    let socket = TcpStream::connect(local_addr)
        .await
        .with_context(|| format!("connect local tcp {}", local_addr))?;
    let (quic_tx, mut quic_rx) = stream.split();
    let (mut reader, mut writer) = socket.into_split();

    let to_quic = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                quic_tx.send_fin().await?;
                break;
            }
            quic_tx.send(Bytes::copy_from_slice(&buf[..n])).await?;
        }
        Result::<()>::Ok(())
    };

    let from_quic = async {
        while let Some(chunk) = quic_rx.recv().await {
            if !chunk.data.is_empty() {
                writer.write_all(&chunk.data).await?;
            }
            if chunk.fin {
                writer.shutdown().await?;
                break;
            }
        }
        Result::<()>::Ok(())
    };

    tokio::try_join!(to_quic, from_quic)?;
    Ok(())
}

async fn forward_udp(local_addr: &str, stream: QuicStreamHandle) -> Result<()> {
    let local = resolve_remote_addr(local_addr).await?;
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let (tx, mut rx) = stream.split();

    let udp = socket.clone();
    let mut recv_task = tokio::spawn(async move {
        let mut decoder = FrameDecoder::new();
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
    stream.send(Bytes::from(frame)).await
}

async fn recv_framed<T>(stream: &mut QuicStreamHandle, decoder: &mut FrameDecoder) -> Result<T>
where
    T: DeserializeOwned,
{
    loop {
        if let Some(result) = decoder.decode_next::<T>() {
            return result;
        }
        let chunk = stream
            .recv()
            .await
            .ok_or_else(|| anyhow!("quic stream closed"))?;
        decoder.push(&chunk.data);
        if chunk.fin {
            if let Some(result) = decoder.decode_next::<T>() {
                return result;
            }
            return Err(anyhow!("quic stream finished before message complete"));
        }
    }
}
