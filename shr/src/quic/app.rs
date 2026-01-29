use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::{quiche, ApplicationOverQuic, QuicResult};

const STREAM_CHANNEL_SIZE: usize = 64;

#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub data: Bytes,
    pub fin: bool,
}

pub struct QuicStreamHandle {
    id: u64,
    outbound: mpsc::Sender<StreamChunk>,
    inbound: mpsc::UnboundedReceiver<StreamChunk>,
    notify: Arc<Notify>,
}

#[derive(Clone)]
pub struct QuicStreamSender {
    id: u64,
    outbound: mpsc::Sender<StreamChunk>,
    notify: Arc<Notify>,
}

pub struct QuicStreamReceiver {
    id: u64,
    inbound: mpsc::UnboundedReceiver<StreamChunk>,
}

impl QuicStreamHandle {
    pub const fn id(&self) -> u64 {
        self.id
    }

    pub fn split(self) -> (QuicStreamSender, QuicStreamReceiver) {
        let sender = QuicStreamSender {
            id: self.id,
            outbound: self.outbound,
            notify: self.notify.clone(),
        };
        let receiver = QuicStreamReceiver {
            id: self.id,
            inbound: self.inbound,
        };
        (sender, receiver)
    }

    pub async fn send(&self, data: Bytes) -> Result<()> {
        QuicStreamSender {
            id: self.id,
            outbound: self.outbound.clone(),
            notify: self.notify.clone(),
        }
        .send(data)
        .await
    }

    pub async fn send_fin(&self) -> Result<()> {
        QuicStreamSender {
            id: self.id,
            outbound: self.outbound.clone(),
            notify: self.notify.clone(),
        }
        .send_fin()
        .await
    }

    pub async fn recv(&mut self) -> Option<StreamChunk> {
        self.inbound.recv().await
    }
}

impl QuicStreamSender {
    pub const fn id(&self) -> u64 {
        self.id
    }

    pub async fn send(&self, data: Bytes) -> Result<()> {
        self.outbound
            .send(StreamChunk { data, fin: false })
            .await
            .map_err(|_| anyhow!("stream outbound channel closed"))?;
        self.notify.notify_one();
        Ok(())
    }

    pub async fn send_fin(&self) -> Result<()> {
        self.outbound
            .send(StreamChunk {
                data: Bytes::new(),
                fin: true,
            })
            .await
            .map_err(|_| anyhow!("stream outbound channel closed"))?;
        self.notify.notify_one();
        Ok(())
    }
}

impl QuicStreamReceiver {
    pub const fn id(&self) -> u64 {
        self.id
    }

    pub async fn recv(&mut self) -> Option<StreamChunk> {
        self.inbound.recv().await
    }
}

pub struct QuicAppHandle {
    cmd_tx: mpsc::Sender<QuicAppCommand>,
    incoming_rx: mpsc::UnboundedReceiver<QuicStreamHandle>,
    control_stream: QuicStreamHandle,
}

pub struct QuicStreamManager {
    cmd_tx: mpsc::Sender<QuicAppCommand>,
    incoming_rx: mpsc::UnboundedReceiver<QuicStreamHandle>,
}

impl QuicAppHandle {
    pub fn split(self) -> (QuicStreamHandle, QuicStreamManager) {
        let manager = QuicStreamManager {
            cmd_tx: self.cmd_tx,
            incoming_rx: self.incoming_rx,
        };
        (self.control_stream, manager)
    }
}

impl QuicStreamManager {
    pub async fn accept_stream(&mut self) -> Option<QuicStreamHandle> {
        self.incoming_rx.recv().await
    }

    pub async fn open_stream(&self, stream_id: u64) -> Result<QuicStreamHandle> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(QuicAppCommand::OpenStream {
                stream_id,
                response: tx,
            })
            .await
            .map_err(|_| anyhow!("quic app command channel closed"))?;
        rx.await.map_err(|_| anyhow!("quic app closed"))?
    }
}

enum QuicAppCommand {
    OpenStream {
        stream_id: u64,
        response: oneshot::Sender<Result<QuicStreamHandle>>,
    },
}

struct StreamState {
    inbound: mpsc::UnboundedSender<StreamChunk>,
    outbound: mpsc::Receiver<StreamChunk>,
    pending: VecDeque<StreamChunk>,
}

pub struct QuicApp {
    streams: HashMap<u64, StreamState>,
    incoming_tx: mpsc::UnboundedSender<QuicStreamHandle>,
    cmd_rx: mpsc::Receiver<QuicAppCommand>,
    notify: Arc<Notify>,
    buffer: Vec<u8>,
}

impl QuicApp {
    pub fn new(control_stream_id: u64) -> (Self, QuicAppHandle) {
        let notify = Arc::new(Notify::new());
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);

        let mut app = Self {
            streams: HashMap::new(),
            incoming_tx,
            cmd_rx,
            notify: notify.clone(),
            buffer: vec![0u8; 64 * 1024],
        };

        let control_stream = app.create_stream(control_stream_id);
        let handle = QuicAppHandle {
            cmd_tx,
            incoming_rx,
            control_stream,
        };

        (app, handle)
    }

    fn create_stream(&mut self, stream_id: u64) -> QuicStreamHandle {
        let (outbound_tx, outbound_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

        let handle = QuicStreamHandle {
            id: stream_id,
            outbound: outbound_tx,
            inbound: inbound_rx,
            notify: self.notify.clone(),
        };

        self.streams.insert(
            stream_id,
            StreamState {
                inbound: inbound_tx,
                outbound: outbound_rx,
                pending: VecDeque::new(),
            },
        );

        tracing::debug!(stream_id, "quic stream created");
        handle
    }

    fn handle_command(&mut self, command: QuicAppCommand) {
        match command {
            QuicAppCommand::OpenStream {
                stream_id,
                response,
            } => {
                if self.streams.contains_key(&stream_id) {
                    let _ = response.send(Err(anyhow!("stream {} already exists", stream_id)));
                    return;
                }
                let handle = self.create_stream(stream_id);
                let _ = response.send(Ok(handle));
            }
        }
    }

    fn drain_commands(&mut self) {
        while let Ok(command) = self.cmd_rx.try_recv() {
            self.handle_command(command);
        }
    }

    fn enqueue_outbound(&mut self) {
        for state in self.streams.values_mut() {
            while let Ok(chunk) = state.outbound.try_recv() {
                state.pending.push_back(chunk);
            }
        }
    }

    fn send_pending(&mut self, qconn: &mut quiche::Connection) -> QuicResult<()> {
        let mut to_remove = Vec::new();

        for (&stream_id, state) in self.streams.iter_mut() {
            while let Some(mut chunk) = state.pending.pop_front() {
                if chunk.fin && !chunk.data.is_empty() {
                    state.pending.push_front(StreamChunk {
                        data: Bytes::new(),
                        fin: true,
                    });
                    chunk.fin = false;
                }

                let send_result = if chunk.data.is_empty() {
                    qconn.stream_send(stream_id, &[], chunk.fin)
                } else {
                    qconn.stream_send(stream_id, &chunk.data, chunk.fin)
                };

                match send_result {
                    Ok(sent) => {
                        if !chunk.data.is_empty() && sent < chunk.data.len() {
                            let remaining = chunk.data.slice(sent..);
                            state.pending.push_front(StreamChunk {
                                data: remaining,
                                fin: false,
                            });
                            break;
                        }
                        if chunk.fin {
                            to_remove.push(stream_id);
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => {
                        state.pending.push_front(chunk);
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(stream_id, error = ?err, "quic stream send failed");
                        return Err(Box::new(err));
                    }
                }
            }
        }

        for stream_id in to_remove {
            self.streams.remove(&stream_id);
        }

        Ok(())
    }
}

impl ApplicationOverQuic for QuicApp {
    fn on_conn_established(
        &mut self,
        _qconn: &mut quiche::Connection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    fn process_reads(&mut self, qconn: &mut quiche::Connection) -> QuicResult<()> {
        for stream_id in qconn.readable() {
            if !self.streams.contains_key(&stream_id) {
                let handle = self.create_stream(stream_id);
                let _ = self.incoming_tx.send(handle);
            }

            let state = match self.streams.get_mut(&stream_id) {
                Some(state) => state,
                None => continue,
            };

            loop {
                match qconn.stream_recv(stream_id, &mut self.buffer) {
                    Ok((read, fin)) => {
                        tracing::debug!(stream_id, bytes = read, fin, "quic stream recv");
                        let chunk = StreamChunk {
                            data: Bytes::copy_from_slice(&self.buffer[..read]),
                            fin,
                        };
                        let _ = state.inbound.send(chunk);
                        if fin {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(err) => return Err(Box::new(err)),
                }
            }
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut quiche::Connection) -> QuicResult<()> {
        self.drain_commands();
        self.enqueue_outbound();
        self.send_pending(qconn)
    }

    async fn wait_for_data(&mut self, _qconn: &mut quiche::Connection) -> QuicResult<()> {
        tokio::select! {
            cmd = self.cmd_rx.recv() => {
                if let Some(command) = cmd {
                    self.handle_command(command);
                }
            }
            _ = self.notify.notified() => {}
        }
        Ok(())
    }
}
