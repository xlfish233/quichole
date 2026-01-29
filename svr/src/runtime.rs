use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use quichole_shr::config::{ServiceType, TlsConfig};
use quichole_shr::protocol::{encode_message, FrameDecoder};
use quichole_shr::protocol::{Ack, Auth, DataChannelCmd, Hello, UdpTraffic, PROTO_V1};
use quichole_shr::quic::{
    QuicApp, QuicStreamHandle, QuicStreamManager, QuicStreamReceiver, QuicStreamSender,
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio_quiche::metrics::{DefaultMetrics, Metrics};
use tokio_quiche::quic::SimpleConnectionIdGenerator;
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
        .ok_or_else(|| anyhow!("tls.cert is required for server"))?;
    let key = tls
        .key
        .as_deref()
        .ok_or_else(|| anyhow!("tls.key is required for server"))?;

    let tls_paths = TlsCertificatePaths {
        cert,
        private_key: key,
        kind: CertificateKind::X509,
    };
    let settings = QuicSettings::default();
    let hooks = Hooks::default();
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
) -> Result<()>
where
    M: Metrics,
{
    let (app, handle) = QuicApp::new(quichole_shr::quic::CONTROL_STREAM_ID);
    let _conn = conn.start(app);

    let (mut control_stream, manager) = handle.split();
    let mut control_decoder = FrameDecoder::new();

    let hello: Hello = recv_framed(&mut control_stream, &mut control_decoder).await?;
    if hello.version() != PROTO_V1 {
        return Err(anyhow!("protocol version mismatch"));
    }

    let handshake = begin_control_handshake(&server, &hello)?;
    send_framed(&control_stream, handshake.nonce()).await?;

    let auth: Auth = recv_framed(&mut control_stream, &mut control_decoder).await?;
    let session = match handshake.verify_auth(&auth) {
        Ok(session) => {
            send_framed(&control_stream, &Ack::Ok).await?;
            session
        }
        Err(err) => {
            send_framed(&control_stream, &Ack::AuthFailed).await?;
            return Err(err);
        }
    };

    let service = session.service().clone();
    let (req_tx, req_rx) = mpsc::channel(64);

    tokio::spawn(async move {
        if let Err(err) = control_task(session, control_stream, manager, req_rx).await {
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
    control_stream: QuicStreamHandle,
    mut manager: QuicStreamManager,
    mut req_rx: mpsc::Receiver<ControlRequest>,
) -> Result<()> {
    while let Some(request) = req_rx.recv().await {
        let (cmd, session_key) = session.create_data_channel();
        send_framed(&control_stream, &cmd).await?;
        send_framed(&control_stream, &session_key).await?;

        let mut data_stream = manager
            .accept_stream()
            .await
            .ok_or_else(|| anyhow!("data stream closed"))?;
        let mut data_decoder = FrameDecoder::new();
        let hello: Hello = recv_framed(&mut data_stream, &mut data_decoder).await?;
        let data_cmd = session.accept_data_channel_hello(&hello)?;
        send_framed(&data_stream, &data_cmd).await?;

        let _ = request.response.send(Ok(PreparedDataStream {
            stream: data_stream,
            mode: data_cmd,
        }));
    }

    Ok(())
}

async fn run_tcp_service(bind_addr: String, req_tx: mpsc::Sender<ControlRequest>) -> Result<()> {
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("bind tcp {}", bind_addr))?;
    tracing::info!(bind_addr = %bind_addr, "tcp service listening");

    loop {
        let (socket, peer) = listener.accept().await?;
        let req_tx = req_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_connection(socket, peer, req_tx).await {
                tracing::warn!(error = %err, "tcp forward failed");
            }
        });
    }
}

async fn handle_tcp_connection(
    socket: TcpStream,
    peer: SocketAddr,
    req_tx: mpsc::Sender<ControlRequest>,
) -> Result<()> {
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
        let (n, peer) = socket.recv_from(&mut buf).await?;
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
    tracing::debug!(peer = %peer, "tcp forwarding finished");
    Ok(())
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
