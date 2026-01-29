use anyhow::{bail, Result};

use super::stream::client_bidi_stream_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    Client,
    Server,
}

/// QUIC 连接的最小状态（只负责分配数据流 ID）
#[derive(Debug, Clone)]
pub struct QuicConnectionState {
    role: ConnectionRole,
    next_data_stream_index: u64,
}

impl QuicConnectionState {
    pub fn new(role: ConnectionRole) -> Self {
        Self {
            role,
            next_data_stream_index: 0,
        }
    }

    pub const fn role(&self) -> ConnectionRole {
        self.role
    }

    /// 分配下一个客户端发起的双向数据流 ID
    pub fn next_data_stream_id(&mut self) -> Result<u64> {
        if self.role != ConnectionRole::Client {
            bail!("only client can allocate data stream id");
        }

        let id = client_bidi_stream_id(self.next_data_stream_index);
        self.next_data_stream_index += 1;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_allocates_stream_ids() {
        let mut state = QuicConnectionState::new(ConnectionRole::Client);

        assert_eq!(state.next_data_stream_id().unwrap(), 4);
        assert_eq!(state.next_data_stream_id().unwrap(), 8);
        assert_eq!(state.next_data_stream_id().unwrap(), 12);
    }

    #[test]
    fn test_server_cannot_allocate_stream_ids() {
        let mut state = QuicConnectionState::new(ConnectionRole::Server);
        assert!(state.next_data_stream_id().is_err());
    }
}
