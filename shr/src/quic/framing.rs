/// 流式消息帧收发函数
///
/// 提供在 QUIC 流上发送和接收带长度前缀消息的统一抽象
use anyhow::{anyhow, Result};
use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};

use super::QuicStreamHandle;
use crate::protocol::{encode_message, FrameDecoder};

/// 发送带长度前缀的消息到 QUIC 流
///
/// # 参数
/// - `stream`: QUIC 流句柄
/// - `msg`: 要发送的消息（必须实现 `Serialize`）
/// - `_with_wait`: 保留参数，仅为兼容旧调用点；V2 协议不再依赖发送 flush 作为同步语义
///
/// # 实现细节
/// - 消息会被序列化并添加 4 字节长度前缀
/// - 返回值仅表示成功入队到应用发送队列，不代表对端已接收
pub async fn send_framed<T>(stream: &QuicStreamHandle, msg: &T, _with_wait: bool) -> Result<()>
where
    T: Serialize,
{
    let frame = encode_message(msg)?;
    tracing::debug!(
        stream_id = stream.id(),
        len = frame.len(),
        "sending framed message"
    );

    stream.send(Bytes::from(frame)).await?;

    Ok(())
}

/// 从 QUIC 流接收带长度前缀的消息
///
/// # 参数
/// - `stream`: QUIC 流句柄（可变引用）
/// - `decoder`: 帧解码器（用于处理分片消息）
///
/// # 返回值
/// 解码后的消息对象
///
/// # 错误
/// - 如果流在消息完整接收前关闭，返回错误
/// - 如果消息格式无效，返回解码错误
pub async fn recv_framed<T>(stream: &mut QuicStreamHandle, decoder: &mut FrameDecoder) -> Result<T>
where
    T: DeserializeOwned,
{
    tracing::debug!(stream_id = stream.id(), "recv_framed: starting");
    loop {
        // 先尝试从解码器缓存中解码
        if let Some(result) = decoder.decode_next::<T>() {
            tracing::debug!(
                stream_id = stream.id(),
                "received framed message from decoder cache"
            );
            return result;
        }

        // 等待下一个数据块
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

        // 将数据推入解码器
        decoder.push(&chunk.data);

        // 如果流结束，尝试最后一次解码
        if chunk.fin {
            if let Some(result) = decoder.decode_next::<T>() {
                return result;
            }
            return Err(anyhow!("quic stream finished before message complete"));
        }
    }
}
