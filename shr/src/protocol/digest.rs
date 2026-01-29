// 摘要计算 - 用于服务名和认证的哈希计算
use sha2::{Digest, Sha256};

/// 摘要长度（SHA-256 输出 32 字节）
pub const DIGEST_LENGTH: usize = 32;

/// Nonce 长度
pub const NONCE_LENGTH: usize = 32;

/// Session key 长度
pub const SESSION_KEY_LENGTH: usize = 32;

/// 计算服务名的 SHA-256 摘要
///
/// 用于在控制通道 Hello 消息中标识服务
pub fn service_digest(service_name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(service_name.as_bytes());
    hasher.finalize().into()
}

/// 计算认证摘要
///
/// 使用 SHA-256(token + nonce) 进行认证
pub fn auth_digest(token: &str, nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(nonce);
    hasher.finalize().into()
}

/// 生成随机 nonce
///
/// 使用加密安全的随机数生成器生成 32 字节的 nonce
pub fn generate_nonce() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce).expect("Failed to generate nonce");
    nonce
}

/// 生成随机 session key
///
/// 使用加密安全的随机数生成器生成 32 字节的 session key
pub fn generate_session_key() -> [u8; 32] {
    generate_nonce()
}

/// 验证认证摘要
///
/// 检查客户端提供的摘要是否与期望的摘要匹配
pub fn verify_auth_digest(client_digest: &[u8; 32], token: &str, nonce: &[u8; 32]) -> bool {
    let expected_digest = auth_digest(token, nonce);
    client_digest == &expected_digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_digest() {
        let service_name = "my_service";
        let digest = service_digest(service_name);

        assert_eq!(digest.len(), 32);

        // 相同的服务名应该产生相同的摘要
        let digest2 = service_digest(service_name);
        assert_eq!(digest, digest2);

        // 不同的服务名应该产生不同的摘要
        let digest3 = service_digest("other_service");
        assert_ne!(digest, digest3);
    }

    #[test]
    fn test_auth_digest() {
        let token = "my_secret_token";
        let nonce = [1u8; 32];

        let digest = auth_digest(token, &nonce);

        assert_eq!(digest.len(), 32);

        // 相同的 token 和 nonce 应该产生相同的摘要
        let digest2 = auth_digest(token, &nonce);
        assert_eq!(digest, digest2);

        // 不同的 token 应该产生不同的摘要
        let digest3 = auth_digest("other_token", &nonce);
        assert_ne!(digest, digest3);

        // 不同的 nonce 应该产生不同的摘要
        let nonce2 = [2u8; 32];
        let digest4 = auth_digest(token, &nonce2);
        assert_ne!(digest, digest4);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        assert_eq!(nonce1.len(), 32);
        assert_eq!(nonce2.len(), 32);

        // 两次生成的 nonce 应该不同（概率上）
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_generate_session_key() {
        let key1 = generate_session_key();
        let key2 = generate_session_key();

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);

        // 两次生成的 session key 应该不同（概率上）
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_service_digest_deterministic() {
        // 测试摘要是确定性的
        let service = "test_service";
        let digests: Vec<_> = (0..10).map(|_| service_digest(service)).collect();

        // 所有摘要应该相同
        for digest in &digests[1..] {
            assert_eq!(&digests[0], digest);
        }
    }

    #[test]
    fn test_auth_digest_deterministic() {
        // 测试认证摘要是确定性的
        let token = "test_token";
        let nonce = [42u8; 32];
        let digests: Vec<_> = (0..10).map(|_| auth_digest(token, &nonce)).collect();

        // 所有摘要应该相同
        for digest in &digests[1..] {
            assert_eq!(&digests[0], digest);
        }
    }

    #[test]
    fn test_nonce_randomness() {
        // 生成多个 nonce，确保它们都不相同
        let nonces: Vec<_> = (0..100).map(|_| generate_nonce()).collect();

        // 检查没有重复（概率上应该不会有）
        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(
                    nonces[i], nonces[j],
                    "Found duplicate nonce at {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(DIGEST_LENGTH, 32);
        assert_eq!(NONCE_LENGTH, 32);
        assert_eq!(SESSION_KEY_LENGTH, 32);
    }

    #[test]
    fn test_verify_auth_digest_success() {
        let token = "test_token";
        let nonce = [42u8; 32];
        let client_digest = auth_digest(token, &nonce);

        assert!(verify_auth_digest(&client_digest, token, &nonce));
    }

    #[test]
    fn test_verify_auth_digest_failure() {
        let token = "test_token";
        let nonce = [42u8; 32];
        let wrong_digest = [0u8; 32];

        assert!(!verify_auth_digest(&wrong_digest, token, &nonce));
    }

    #[test]
    fn test_verify_auth_digest_wrong_token() {
        let token = "test_token";
        let nonce = [42u8; 32];
        let client_digest = auth_digest(token, &nonce);

        // 使用错误的 token 验证
        assert!(!verify_auth_digest(&client_digest, "wrong_token", &nonce));
    }

    #[test]
    fn test_verify_auth_digest_wrong_nonce() {
        let token = "test_token";
        let nonce = [42u8; 32];
        let client_digest = auth_digest(token, &nonce);

        // 使用错误的 nonce 验证
        let wrong_nonce = [99u8; 32];
        assert!(!verify_auth_digest(&client_digest, token, &wrong_nonce));
    }
}
