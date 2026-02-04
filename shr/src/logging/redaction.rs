//! Sensitive data redaction for logs.
//!
//! # Redaction Policy
//!
//! - **Tokens**: Always fully redacted (never show any part)
//! - **Nonces** (32 bytes): Show only first byte in hex
//! - **Session keys** (32 bytes): Show only first byte in hex
//! - **Auth digests** (32 bytes): Show only first byte in hex
//! - **Service digests** (32 bytes): Show only first byte in hash (safe, it's a hash)
//! - **Payload data**: Truncate to 32 bytes in DEBUG logs

use std::fmt;

/// Redact a token value completely (never show partial)
///
/// # Example
/// ```
/// use quichole_shr::logging::redaction::redact_token;
/// assert_eq!(redact_token("my_secret_token"), "***REDACTED***");
/// ```
pub fn redact_token(_token: &str) -> &'static str {
    "***REDACTED***"
}

/// Redact a 32-byte cryptographic value (nonce, session_key, digest)
///
/// Shows only the first byte in hex format, followed by "***REDACTED***".
///
/// # Example
/// ```
/// use quichole_shr::logging::redaction::redact_bytes_32;
/// let bytes = [0xAB, 0xCD, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04,
///              0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
///              0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
///              0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C];
/// assert_eq!(redact_bytes_32(&bytes), "ab***REDACTED***");
/// ```
pub fn redact_bytes_32(bytes: &[u8; 32]) -> String {
    format!("{:02x}***REDACTED***", bytes[0])
}

/// Truncate payload data for DEBUG logs
pub fn truncate_payload(data: &[u8], max_len: usize) -> &[u8] {
    if data.len() > max_len {
        &data[..max_len]
    } else {
        data
    }
}

/// Convenience wrapper for redacting protocol handshake data
///
/// # Usage
/// ```ignore
/// use quichole_shr::logging::RedactedNonce;
/// tracing::debug!(nonce = %RedactedNonce(nonce), "handshake");
/// // Output: nonce=ab***REDACTED***
/// ```
pub struct RedactedNonce(pub [u8; 32]);
pub struct RedactedSessionKey(pub [u8; 32]);
pub struct RedactedAuthDigest(pub [u8; 32]);
pub struct RedactedServiceDigest(pub [u8; 32]);

impl fmt::Display for RedactedNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}***REDACTED***", self.0[0])
    }
}

impl fmt::Display for RedactedSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}***REDACTED***", self.0[0])
    }
}

impl fmt::Display for RedactedAuthDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}***REDACTED***", self.0[0])
    }
}

impl fmt::Display for RedactedServiceDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Service digest is a hash of service name, safe to show first byte
        write!(f, "{:02x}***", self.0[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_token() {
        assert_eq!(redact_token("my_secret_token_123"), "***REDACTED***");
        assert_eq!(redact_token(""), "***REDACTED***");
        assert_eq!(redact_token("a"), "***REDACTED***");
    }

    #[test]
    fn test_redact_bytes_32_shows_only_first_byte() {
        let bytes = [0xAB; 32];
        let redacted = redact_bytes_32(&bytes);
        assert_eq!(redacted, "ab***REDACTED***");

        let mut bytes2 = [0u8; 32];
        bytes2[0] = 0xCD;
        bytes2[1] = 0xEF;
        bytes2[2] = 0x00;
        bytes2[3] = 0x01;
        let redacted2 = redact_bytes_32(&bytes2);
        assert_eq!(redacted2, "cd***REDACTED***");
        assert!(!redacted2.contains("ef"));
        assert!(!redacted2.contains("00"));
    }

    #[test]
    fn test_redacted_nonce_display() {
        let nonce = [0x12; 32];
        let redacted = RedactedNonce(nonce);
        assert_eq!(format!("{}", redacted), "12***REDACTED***");
    }

    #[test]
    fn test_redacted_session_key_display() {
        let key = [0xFF; 32];
        let redacted = RedactedSessionKey(key);
        assert_eq!(format!("{}", redacted), "ff***REDACTED***");
    }

    #[test]
    fn test_redacted_auth_digest_display() {
        let digest = [0x00; 32];
        let redacted = RedactedAuthDigest(digest);
        assert_eq!(format!("{}", redacted), "00***REDACTED***");
    }

    #[test]
    fn test_truncate_payload() {
        let data = vec![0u8; 100];
        let truncated = truncate_payload(&data, 32);
        assert_eq!(truncated.len(), 32);

        let small_data = vec![0u8; 10];
        let not_truncated = truncate_payload(&small_data, 32);
        assert_eq!(not_truncated.len(), 10);
    }
}
