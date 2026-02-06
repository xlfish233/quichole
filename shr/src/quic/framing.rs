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
/// - `with_yield`: 是否在发送后执行 yield（服务端需要）
///
/// # 实现细节
/// - 消息会被序列化并添加 4 字节长度前缀
/// - 服务端模式下（`with_yield = true`）会在发送后执行 10 次 `yield_now()`
///   以确保数据有机会被发送到网络
pub async fn send_framed<T>(stream: &QuicStreamHandle, msg: &T, with_yield: bool) -> Result<()>
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

    if with_yield {
        // 确保数据有机会被发送到网络
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

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
