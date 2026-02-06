/// TCP 流与 QUIC 流之间的双向转发
///
/// 提供统一的 TCP 和 QUIC 流双向转发逻辑
use anyhow::Result;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::QuicStreamHandle;

/// TCP 流与 QUIC 流之间的双向转发
///
/// # 参数
/// - `tcp`: TCP 连接
/// - `quic`: QUIC 流句柄
/// - `pending`: 预读的数据（用于客户端在建立连接前已经接收到的数据）
/// - `peer_label`: 用于日志的对端标识（如 "peer=1.2.3.4:8080" 或 "local=127.0.0.1:80"）
///
/// # 实现细节
/// - 使用 16KB 缓冲区进行数据读取
/// - 支持处理预读数据（如果提供）
/// - 双向并发转发，任一方向出错或关闭时整个转发结束
pub async fn forward_tcp_bidirectional(
    tcp: TcpStream,
    quic: QuicStreamHandle,
    pending: Option<Bytes>,
    peer_label: String,
) -> Result<()> {
    let stream_id = quic.id();
    tracing::debug!(peer = %peer_label, stream_id, "tcp forwarding started");

    let (quic_tx, mut quic_rx) = quic.split();
    let (mut reader, mut writer) = tcp.into_split();

    // TCP -> QUIC
    let to_quic = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            tracing::debug!(peer = %peer_label, stream_id, bytes = n, "tcp->quic read");
            if n == 0 {
                quic_tx.send_fin().await?;
                break;
            }
            quic_tx.send(Bytes::copy_from_slice(&buf[..n])).await?;
            tracing::debug!(peer = %peer_label, stream_id, bytes = n, "tcp->quic sent");
        }
        Result::<()>::Ok(())
    };

    // QUIC -> TCP
    let from_quic = async {
        // 先处理预读数据（如果有）
        if let Some(pending_data) = pending {
            tracing::debug!(
                peer = %peer_label,
                stream_id,
                bytes = pending_data.len(),
                "quic->tcp pending"
            );
            writer.write_all(&pending_data).await?;
        }

        while let Some(chunk) = quic_rx.recv().await {
            if !chunk.data.is_empty() {
                tracing::debug!(
                    peer = %peer_label,
                    stream_id,
                    bytes = chunk.data.len(),
                    "quic->tcp recv"
                );
                writer.write_all(&chunk.data).await?;
            }
            if chunk.fin {
                tracing::debug!(peer = %peer_label, stream_id, "quic->tcp fin");
                writer.shutdown().await?;
                break;
            }
        }
        Result::<()>::Ok(())
    };

    tokio::try_join!(to_quic, from_quic)?;
    tracing::debug!(peer = %peer_label, stream_id, "tcp forwarding finished");
    Ok(())
}
