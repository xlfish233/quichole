// 编解码器 - 用于在流中读写消息
use anyhow::{Context, Result};
use bytes::{Buf, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 最大消息大小 (1MB)
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// 获取最大消息大小
pub const fn max_message_size() -> u32 {
    MAX_MESSAGE_SIZE
}

/// 检查消息大小是否有效
pub fn is_valid_message_size(size: u32) -> bool {
    size > 0 && size <= MAX_MESSAGE_SIZE
}

/// 写入消息到流
///
/// 消息格式：
/// ```text
/// +------------------+------------------+
/// |  Length (4 bytes)|  Payload         |
/// |  (big-endian)    |  (bincode)       |
/// +------------------+------------------+
/// ```
pub async fn write_message<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWriteExt + Unpin,
{
    let payload = bincode::serialize(msg).context("Failed to serialize message")?;

    let len = payload.len() as u32;

    writer
        .write_u32(len)
        .await
        .context("Failed to write message length")?;

    writer
        .write_all(&payload)
        .await
        .context("Failed to write message payload")?;

    writer.flush().await.context("Failed to flush writer")?;

    Ok(())
}

/// 将消息编码为长度前缀帧
pub fn encode_message<T>(msg: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let payload = bincode::serialize(msg).context("Failed to serialize message")?;
    let len = payload.len() as u32;

    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// 流式消息帧解码器
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn take_remaining(&mut self) -> BytesMut {
        std::mem::take(&mut self.buffer)
    }

    pub fn decode_next<T>(&mut self) -> Option<Result<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        if self.buffer.len() < 4 {
            return None;
        }

        let len = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;

        if len > MAX_MESSAGE_SIZE as usize {
            return Some(Err(anyhow::anyhow!("Message too large: {} bytes", len)));
        }

        if self.buffer.len() < 4 + len {
            return None;
        }

        self.buffer.advance(4);
        let payload = self.buffer.split_to(len);
        let msg = bincode::deserialize(&payload).context("Failed to deserialize message");
        Some(msg)
    }
}

/// 从流读取消息
pub async fn read_message<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncReadExt + Unpin,
{
    let len = reader
        .read_u32()
        .await
        .context("Failed to read message length")?;

    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("Message too large: {} bytes", len);
    }

    let mut payload = vec![0u8; len as usize];
    reader
        .read_exact(&mut payload)
        .await
        .context("Failed to read message payload")?;

    let msg = bincode::deserialize(&payload).context("Failed to deserialize message")?;

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;

    #[tokio::test]
    async fn test_write_and_read_hello() {
        let mut buffer = Vec::new();

        let hello = Hello::ControlChannelHello {
            version: PROTO_V1,
            service_digest: [0u8; 32],
        };

        write_message(&mut buffer, &hello).await.unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded: Hello = read_message(&mut cursor).await.unwrap();

        assert_eq!(hello, decoded);
    }

    #[tokio::test]
    async fn test_write_and_read_auth() {
        let mut buffer = Vec::new();

        let auth = Auth { digest: [1u8; 32] };

        write_message(&mut buffer, &auth).await.unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded: Auth = read_message(&mut cursor).await.unwrap();

        assert_eq!(auth, decoded);
    }

    #[tokio::test]
    async fn test_write_and_read_ack() {
        let mut buffer = Vec::new();

        let ack = Ack::Ok;

        write_message(&mut buffer, &ack).await.unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded: Ack = read_message(&mut cursor).await.unwrap();

        assert_eq!(ack, decoded);
    }

    #[tokio::test]
    async fn test_write_and_read_control_cmd() {
        let mut buffer = Vec::new();

        let cmd = ControlChannelCmd::Heartbeat;

        write_message(&mut buffer, &cmd).await.unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded: ControlChannelCmd = read_message(&mut cursor).await.unwrap();

        assert_eq!(cmd, decoded);
    }

    #[tokio::test]
    async fn test_write_and_read_data_cmd() {
        let mut buffer = Vec::new();

        let cmd = DataChannelCmd::StartForwardTcp;

        write_message(&mut buffer, &cmd).await.unwrap();

        let mut cursor = std::io::Cursor::new(buffer);
        let decoded: DataChannelCmd = read_message(&mut cursor).await.unwrap();

        assert_eq!(cmd, decoded);
    }

    #[tokio::test]
    async fn test_read_message_with_invalid_length() {
        let mut buffer = Vec::new();
        buffer.write_u32(u32::MAX).await.unwrap(); // 无效的长度

        let mut cursor = std::io::Cursor::new(buffer);
        let result: Result<Hello> = read_message(&mut cursor).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_read_message_with_incomplete_data() {
        let mut buffer = Vec::new();
        buffer.write_u32(100).await.unwrap(); // 声称有 100 字节
        buffer.write_all(&[0u8; 10]).await.unwrap(); // 但只有 10 字节

        let mut cursor = std::io::Cursor::new(buffer);
        let result: Result<Hello> = read_message(&mut cursor).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multiple_messages() {
        let mut buffer = Vec::new();

        // 写入多个消息
        let hello = Hello::ControlChannelHello {
            version: PROTO_V1,
            service_digest: [0u8; 32],
        };
        write_message(&mut buffer, &hello).await.unwrap();

        let auth = Auth { digest: [1u8; 32] };
        write_message(&mut buffer, &auth).await.unwrap();

        let ack = Ack::Ok;
        write_message(&mut buffer, &ack).await.unwrap();

        // 读取多个消息
        let mut cursor = std::io::Cursor::new(buffer);

        let decoded_hello: Hello = read_message(&mut cursor).await.unwrap();
        assert_eq!(hello, decoded_hello);

        let decoded_auth: Auth = read_message(&mut cursor).await.unwrap();
        assert_eq!(auth, decoded_auth);

        let decoded_ack: Ack = read_message(&mut cursor).await.unwrap();
        assert_eq!(ack, decoded_ack);
    }

    #[test]
    fn test_max_message_size() {
        assert_eq!(max_message_size(), 1024 * 1024);
    }

    #[test]
    fn test_is_valid_message_size() {
        assert!(is_valid_message_size(1));
        assert!(is_valid_message_size(1024));
        assert!(is_valid_message_size(1024 * 1024));

        assert!(!is_valid_message_size(0));
        assert!(!is_valid_message_size(1024 * 1024 + 1));
        assert!(!is_valid_message_size(u32::MAX));
    }

    #[test]
    fn test_frame_decoder_partial_and_complete() {
        let hello = Hello::ControlChannelHello {
            version: PROTO_V1,
            service_digest: [3u8; 32],
        };
        let frame = encode_message(&hello).unwrap();

        let mut decoder = FrameDecoder::new();
        decoder.push(&frame[..3]);
        assert!(decoder.decode_next::<Hello>().is_none());

        decoder.push(&frame[3..]);
        let decoded = decoder.decode_next::<Hello>().unwrap().unwrap();
        assert_eq!(decoded, hello);
    }

    #[test]
    fn test_frame_decoder_multiple_messages() {
        let hello = Hello::ControlChannelHello {
            version: PROTO_V1,
            service_digest: [4u8; 32],
        };
        let auth = Auth { digest: [9u8; 32] };

        let mut decoder = FrameDecoder::new();
        decoder.push(&encode_message(&hello).unwrap());
        decoder.push(&encode_message(&auth).unwrap());

        let decoded_hello = decoder.decode_next::<Hello>().unwrap().unwrap();
        let decoded_auth = decoder.decode_next::<Auth>().unwrap().unwrap();
        assert_eq!(decoded_hello, hello);
        assert_eq!(decoded_auth, auth);
        assert!(decoder.decode_next::<Auth>().is_none());
    }

    #[test]
    fn test_frame_decoder_too_large() {
        let mut decoder = FrameDecoder::new();
        decoder.push(&u32::MAX.to_be_bytes());
        let err = decoder.decode_next::<Hello>().unwrap().unwrap_err();
        assert!(err.to_string().contains("too large"));
    }
}
