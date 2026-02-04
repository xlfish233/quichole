use uuid::Uuid;

/// Connection identifier for tracking QUIC connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(Uuid);

impl ConnectionId {
    /// Generate a new connection ID using UUID v4
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a ConnectionId from a u64 value
    /// Useful for compatibility with QUIC internal IDs
    pub fn from_u64(id: u64) -> Self {
        // Construct a UUID from the u64 value
        // This creates a UUID where the first 8 bytes are the u64 value
        let bytes = id.to_be_bytes();
        let uuid = Uuid::from_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], 0, 0,
            0, 0, 0, 0, 0, 0,
        ]);
        Self(uuid)
    }

    /// Get the short display format (first 8 characters)
    pub fn short(&self) -> String {
        self.0.to_string()[..8].to_string()
    }

    /// Get the underlying UUID
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conn_{}", self.0)
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

/// QUIC stream identifier for tracking individual streams within a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(u64);

impl StreamId {
    /// Create a new StreamId from a u64 value
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the underlying u64 value
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Check if this is a client-initiated stream (odd number)
    pub fn is_client_initiated(&self) -> bool {
        self.0 % 2 == 1
    }

    /// Check if this is a server-initiated stream (even number)
    pub fn is_server_initiated(&self) -> bool {
        self.0.is_multiple_of(2)
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "stream-{}", self.0)
    }
}

impl From<u64> for StreamId {
    fn from(id: u64) -> Self {
        Self::new(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_generation() {
        let id1 = ConnectionId::new();
        let id2 = ConnectionId::new();

        // Each new ID should be unique
        assert_ne!(id1, id2);

        // Short format should be 8 characters
        assert_eq!(id1.short().len(), 8);
        assert_eq!(id2.short().len(), 8);
    }

    #[test]
    fn test_connection_id_from_u64() {
        let id = ConnectionId::from_u64(0x1234567890ABCDEF);
        let short = id.short();

        // Short format should contain the hex representation
        assert_eq!(short.len(), 8);
    }

    #[test]
    fn test_connection_id_display() {
        let id = ConnectionId::new();
        let display = format!("{}", id);

        // Display should start with "conn_" prefix
        assert!(display.starts_with("conn_"));
        assert!(display.len() > 5); // "conn_" + UUID
    }

    #[test]
    fn test_connection_id_copy() {
        let id1 = ConnectionId::new();
        let id2 = id1; // Should work because of Copy trait

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_stream_id_creation() {
        let id = StreamId::new(42);
        assert_eq!(id.as_u64(), 42);
    }

    #[test]
    fn test_stream_id_from_u64() {
        let id: StreamId = 123.into();
        assert_eq!(id.as_u64(), 123);
    }

    #[test]
    fn test_stream_id_display() {
        let id = StreamId::new(42);
        let display = format!("{}", id);
        assert_eq!(display, "stream-42");
    }

    #[test]
    fn test_stream_id_direction() {
        let client_stream = StreamId::new(1); // Odd = client
        let server_stream = StreamId::new(2); // Even = server

        assert!(client_stream.is_client_initiated());
        assert!(!client_stream.is_server_initiated());
        assert!(server_stream.is_server_initiated());
        assert!(!server_stream.is_client_initiated());
    }

    #[test]
    fn test_stream_id_copy() {
        let id1 = StreamId::new(42);
        let id2 = id1; // Should work because of Copy trait

        assert_eq!(id1, id2);
        assert_eq!(id1.as_u64(), 42);
        assert_eq!(id2.as_u64(), 42);
    }
}
