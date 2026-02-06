use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::collections::{HashMap, HashSet, VecDeque};
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
        let chunk = self.inbound.recv().await;
        if chunk.is_none() {
            tracing::warn!(stream_id = self.id, "stream inbound channel closed");
        }
        chunk
    }
}

impl QuicStreamSender {
    pub const fn id(&self) -> u64 {
        self.id
    }

    pub async fn send(&self, data: Bytes) -> Result<()> {
        tracing::trace!(
            stream_id = self.id,
            len = data.len(),
            "QuicStreamSender::send"
        );
        self.outbound
            .send(StreamChunk { data, fin: false })
            .await
            .map_err(|_| anyhow!("stream outbound channel closed"))?;
        tracing::trace!(stream_id = self.id, "QuicStreamSender::send - notifying");
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
    seen_streams: HashSet<u64>,
    incoming_tx: mpsc::UnboundedSender<QuicStreamHandle>,
    cmd_rx: mpsc::Receiver<QuicAppCommand>,
    cmd_rx_closed_logged: bool,
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
            seen_streams: HashSet::new(),
            incoming_tx,
            cmd_rx,
            cmd_rx_closed_logged: false,
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
        self.seen_streams.insert(stream_id);
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
                if self.seen_streams.contains(&stream_id) {
                    let _ = response.send(Err(anyhow!("stream {} already used", stream_id)));
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
        let mut enqueued = 0;
        for (stream_id, state) in self.streams.iter_mut() {
            while let Ok(chunk) = state.outbound.try_recv() {
                tracing::trace!(
                    stream_id,
                    data_len = chunk.data.len(),
                    fin = chunk.fin,
                    "enqueuing chunk"
                );
                state.pending.push_back(chunk);
                enqueued += 1;
            }
        }
        if enqueued > 0 {
            tracing::debug!(enqueued, "enqueued outbound chunks");
        }
    }

    fn normalize_chunk_before_send(state: &mut StreamState, chunk: &mut StreamChunk) {
        if chunk.fin && !chunk.data.is_empty() {
            state.pending.push_front(StreamChunk {
                data: Bytes::new(),
                fin: true,
            });
            chunk.fin = false;
        }
    }

    fn send_pending_chunk(
        qconn: &mut quiche::Connection,
        stream_id: u64,
        state: &mut StreamState,
        mut chunk: StreamChunk,
        total_sent: &mut usize,
        to_remove: &mut Vec<u64>,
    ) -> QuicResult<bool> {
        tracing::trace!(
            stream_id,
            data_len = chunk.data.len(),
            fin = chunk.fin,
            "attempting to send chunk"
        );

        Self::normalize_chunk_before_send(state, &mut chunk);

        let send_result = if chunk.data.is_empty() {
            qconn.stream_send(stream_id, &[], chunk.fin)
        } else {
            qconn.stream_send(stream_id, &chunk.data, chunk.fin)
        };

        match send_result {
            Ok(sent) => {
                tracing::trace!(stream_id, sent, total = chunk.data.len(), "sent bytes");
                *total_sent += sent;

                if !chunk.data.is_empty() && sent < chunk.data.len() {
                    let remaining = chunk.data.slice(sent..);
                    tracing::debug!(
                        stream_id,
                        remaining = remaining.len(),
                        "partial send, requeueing"
                    );
                    state.pending.push_front(StreamChunk {
                        data: remaining,
                        fin: false,
                    });
                    return Ok(true);
                }

                if chunk.fin {
                    tracing::debug!(stream_id, "stream finished, marking for removal");
                    to_remove.push(stream_id);
                    return Ok(true);
                }

                Ok(false)
            }
            Err(quiche::Error::Done) => {
                tracing::trace!(stream_id, "send would block, requeueing");
                state.pending.push_front(chunk);
                Ok(true)
            }
            Err(err) => {
                tracing::warn!(stream_id, error = ?err, "quic stream send failed");
                Err(Box::new(err))
            }
        }
    }

    fn send_pending(&mut self, qconn: &mut quiche::Connection) -> QuicResult<()> {
        let mut to_remove = Vec::new();
        let mut total_sent = 0;

        for (&stream_id, state) in self.streams.iter_mut() {
            while let Some(chunk) = state.pending.pop_front() {
                let should_break = Self::send_pending_chunk(
                    qconn,
                    stream_id,
                    state,
                    chunk,
                    &mut total_sent,
                    &mut to_remove,
                )?;

                if should_break {
                    break;
                }
            }
        }

        if total_sent > 0 {
            tracing::debug!(total_sent, "total bytes sent in this cycle");
        }

        for stream_id in to_remove {
            tracing::debug!(stream_id, "removing finished stream");
            self.streams.remove(&stream_id);
        }

        Ok(())
    }

    fn should_drop_reused_stream(&self, stream_id: u64) -> bool {
        self.seen_streams.contains(&stream_id) && !self.streams.contains_key(&stream_id)
    }

    fn ensure_incoming_stream_state(&mut self, stream_id: u64) {
        if !self.streams.contains_key(&stream_id) {
            tracing::debug!(stream_id, "creating new stream for incoming data");
            let handle = self.create_stream(stream_id);
            let _ = self.incoming_tx.send(handle);
        }
    }

    fn drain_reused_stream_data(
        qconn: &mut quiche::Connection,
        stream_id: u64,
        buffer: &mut [u8],
    ) -> QuicResult<()> {
        loop {
            match qconn.stream_recv(stream_id, buffer) {
                Ok((_read, fin)) => {
                    if fin {
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    tracing::error!(stream_id, error = ?err, "quic stream recv error");
                    return Err(Box::new(err));
                }
            }
        }

        Ok(())
    }

    fn recv_stream_chunks(
        qconn: &mut quiche::Connection,
        stream_id: u64,
        buffer: &mut [u8],
        state: &mut StreamState,
    ) -> QuicResult<()> {
        loop {
            match qconn.stream_recv(stream_id, buffer) {
                Ok((read, fin)) => {
                    tracing::debug!(stream_id, bytes = read, fin, "quic stream recv");
                    let chunk = StreamChunk {
                        data: Bytes::copy_from_slice(&buffer[..read]),
                        fin,
                    };
                    if let Err(err) = state.inbound.send(chunk) {
                        tracing::error!(stream_id, "failed to send to inbound channel: {:?}", err);
                    }
                    if fin {
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    tracing::error!(stream_id, error = ?err, "quic stream recv error");
                    return Err(Box::new(err));
                }
            }
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
        let readable_streams: Vec<u64> = qconn.readable().collect();
        tracing::debug!(
            readable_count = readable_streams.len(),
            streams = ?readable_streams,
            "processing readable streams"
        );

        for stream_id in readable_streams {
            if self.should_drop_reused_stream(stream_id) {
                tracing::warn!(stream_id, "dropping data for reused stream id");
                Self::drain_reused_stream_data(qconn, stream_id, &mut self.buffer)?;
                continue;
            }

            self.ensure_incoming_stream_state(stream_id);

            let state = match self.streams.get_mut(&stream_id) {
                Some(state) => state,
                None => {
                    tracing::warn!(stream_id, "stream disappeared after creation");
                    continue;
                }
            };

            Self::recv_stream_chunks(qconn, stream_id, &mut self.buffer, state)?;
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut quiche::Connection) -> QuicResult<()> {
        tracing::trace!("process_writes: draining commands");
        self.drain_commands();
        tracing::trace!("process_writes: enqueuing outbound");
        self.enqueue_outbound();
        tracing::trace!(
            pending_streams = self.streams.len(),
            "process_writes: sending pending"
        );
        self.send_pending(qconn)
    }

    async fn wait_for_data(&mut self, _qconn: &mut quiche::Connection) -> QuicResult<()> {
        tracing::trace!("wait_for_data: waiting for events");
        tokio::select! {
            cmd = self.cmd_rx.recv() => {
                if let Some(command) = cmd {
                    tracing::debug!("wait_for_data: received command");
                    self.handle_command(command);
                } else {
                    if !self.cmd_rx_closed_logged {
                        tracing::debug!("wait_for_data: command channel closed");
                        self.cmd_rx_closed_logged = true;
                    }
                    // The io worker may call `wait_for_data` in a loop. If the command channel is
                    // closed, `recv()` will return immediately, which would otherwise spin.
                    self.notify.notified().await;
                }
            }
            _ = self.notify.notified() => {
                tracing::trace!("wait_for_data: notified");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rejects_reused_stream_id() {
        let (mut app, _handle) = QuicApp::new(0);

        let (tx, rx) = oneshot::channel();
        app.handle_command(QuicAppCommand::OpenStream {
            stream_id: 4,
            response: tx,
        });
        let _ = rx.await.unwrap().unwrap();
        app.streams.remove(&4);

        let (tx, rx) = oneshot::channel();
        app.handle_command(QuicAppCommand::OpenStream {
            stream_id: 4,
            response: tx,
        });
        let result = rx.await.unwrap();
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("already used"));
    }
}
