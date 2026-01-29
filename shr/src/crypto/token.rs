use crate::protocol::auth_digest;

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }

    diff == 0
}

/// 计算认证摘要（SHA-256(token + nonce)）
pub fn compute_auth_digest(token: &str, nonce: &[u8; 32]) -> [u8; 32] {
    auth_digest(token, nonce)
}

/// 常量时间对比认证摘要
pub fn verify_auth_digest(client_digest: &[u8; 32], token: &str, nonce: &[u8; 32]) -> bool {
    let expected = auth_digest(token, nonce);
    constant_time_eq(client_digest, &expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_auth_digest_matches_protocol() {
        let token = "test_token";
        let nonce = [7u8; 32];
        let digest = compute_auth_digest(token, &nonce);
        let expected = auth_digest(token, &nonce);

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_verify_auth_digest_success() {
        let token = "test_token";
        let nonce = [8u8; 32];
        let digest = auth_digest(token, &nonce);

        assert!(verify_auth_digest(&digest, token, &nonce));
    }

    #[test]
    fn test_verify_auth_digest_failure() {
        let token = "test_token";
        let nonce = [9u8; 32];
        let digest = [0u8; 32];

        assert!(!verify_auth_digest(&digest, token, &nonce));
    }

    #[test]
    fn test_verify_auth_digest_wrong_token() {
        let token = "test_token";
        let nonce = [10u8; 32];
        let digest = auth_digest(token, &nonce);

        assert!(!verify_auth_digest(&digest, "wrong_token", &nonce));
    }
}
