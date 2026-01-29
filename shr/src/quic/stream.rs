/// 控制流 Stream ID（客户端发起双向流）
pub const CONTROL_STREAM_ID: u64 = 0;

/// 客户端发起双向数据流的最小 ID（4 的倍数）
pub const CLIENT_BIDI_STREAM_BASE: u64 = 4;

/// 判断是否为控制流
pub const fn is_control_stream_id(id: u64) -> bool {
    id == CONTROL_STREAM_ID
}

/// 将数据流索引转换为客户端发起双向流 ID
///
/// index 从 0 开始，对应 Stream ID = 4 * (index + 1)
pub const fn client_bidi_stream_id(index: u64) -> u64 {
    CLIENT_BIDI_STREAM_BASE * (index + 1)
}

/// 判断是否为客户端发起的双向数据流
pub const fn is_client_bidi_stream_id(id: u64) -> bool {
    id != CONTROL_STREAM_ID && id.is_multiple_of(CLIENT_BIDI_STREAM_BASE)
}

/// 从客户端双向数据流 ID 还原索引
pub const fn data_stream_index_from_id(id: u64) -> Option<u64> {
    if is_client_bidi_stream_id(id) {
        Some(id / CLIENT_BIDI_STREAM_BASE - 1)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_stream_id() {
        assert!(is_control_stream_id(0));
        assert!(!is_control_stream_id(4));
    }

    #[test]
    fn test_client_bidi_stream_id() {
        assert_eq!(client_bidi_stream_id(0), 4);
        assert_eq!(client_bidi_stream_id(1), 8);
        assert_eq!(client_bidi_stream_id(2), 12);
    }

    #[test]
    fn test_is_client_bidi_stream_id() {
        assert!(!is_client_bidi_stream_id(0));
        assert!(is_client_bidi_stream_id(4));
        assert!(is_client_bidi_stream_id(8));
        assert!(!is_client_bidi_stream_id(1));
        assert!(!is_client_bidi_stream_id(2));
        assert!(!is_client_bidi_stream_id(3));
        assert!(!is_client_bidi_stream_id(5));
    }

    #[test]
    fn test_data_stream_index_from_id() {
        assert_eq!(data_stream_index_from_id(4), Some(0));
        assert_eq!(data_stream_index_from_id(8), Some(1));
        assert_eq!(data_stream_index_from_id(12), Some(2));
        assert_eq!(data_stream_index_from_id(0), None);
        assert_eq!(data_stream_index_from_id(2), None);
        assert_eq!(data_stream_index_from_id(3), None);
    }
}
