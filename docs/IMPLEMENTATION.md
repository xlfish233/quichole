# Quichole TDD 实施指南

本文档提供了使用 TDD（测试驱动开发）方法实现 quichole 的详细指南。

## 目录

- [TDD 原则](#tdd-原则)
- [项目结构](#项目结构)
- [Phase 1: 协议模块](#phase-1-协议模块)
- [Phase 2: 配置模块](#phase-2-配置模块)
- [Phase 3: 加密模块](#phase-3-加密模块)
- [Phase 4: QUIC 基础](#phase-4-quic-基础)
- [Phase 5: 服务端实现](#phase-5-服务端实现)
- [Phase 6: 客户端实现](#phase-6-客户端实现)
- [Phase 7: 集成测试](#phase-7-集成测试)

## TDD 原则

### 红-绿-重构循环

每个功能的开发都遵循以下步骤：

1. **🔴 红（Red）- 写失败的测试**
   ```bash
   # 先写测试
   # 运行测试，确认失败
   cargo test
   ```

2. **🟢 绿（Green）- 让测试通过**
   ```bash
   # 编写最小化的实现代码
   # 运行测试，确认通过
   cargo test
   ```

3. **🔵 重构（Refactor）- 优化代码**
   ```bash
   # 重构代码，消除重复
   # 运行测试，确保仍然通过
   cargo test
   ```

### 测试原则

- ✅ 测试先行，代码后行
- ✅ 每次只测试一个功能点
- ✅ 测试应该快速、独立、可重复
- ✅ 测试覆盖率目标 >80%
- ✅ 使用有意义的测试名称

## 项目结构

```
quichole/
├── Cargo.toml              # Workspace 配置
├── shr/                    # 共享库
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── protocol/       # Phase 1
│   │   │   ├── mod.rs
│   │   │   ├── message.rs
│   │   │   ├── codec.rs
│   │   │   └── digest.rs
│   │   ├── config/         # Phase 2
│   │   │   ├── mod.rs
│   │   │   ├── server.rs
│   │   │   ├── client.rs
│   │   │   └── common.rs
│   │   ├── crypto/         # Phase 3
│   │   │   ├── mod.rs
│   │   │   └── token.rs
│   │   └── quic/           # Phase 4
│   │       ├── mod.rs
│   │       ├── connection.rs
│   │       └── stream.rs
│   └── tests/              # 集成测试
├── svr/                    # 服务端 (Phase 5)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs
│   │   ├── server.rs
│   │   ├── service.rs
│   │   └── connection.rs
│   └── tests/
└── cli/                    # 客户端 (Phase 6)
    ├── Cargo.toml
    ├── src/
    │   ├── main.rs
    │   ├── client.rs
    │   ├── service.rs
    │   └── connection.rs
    └── tests/
```

## Phase 1: 协议模块

### Step 1.1: 消息类型定义

#### 🔴 红：写测试

创建 `shr/src/protocol/message.rs`：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_control_channel_serialization() {
        let hello = Hello::ControlChannelHello {
            version: 1,
            service_digest: [0u8; 32],
        };
        
        let encoded = bincode::serialize(&hello).unwrap();
        let decoded: Hello = bincode::deserialize(&encoded).unwrap();
        
        assert_eq!(hello, decoded);
    }

    #[test]
    fn test_hello_data_channel_serialization() {
        let hello = Hello::DataChannelHello {
            version: 1,
            session_key: [1u8; 32],
        };
        
        let encoded = bincode::serialize(&hello).unwrap();
        let decoded: Hello = bincode::deserialize(&encoded).unwrap();
        
        assert_eq!(hello, decoded);
    }

    #[test]
    fn test_auth_serialization() {
        let auth = Auth {
            digest: [2u8; 32],
        };
        
        let encoded = bincode::serialize(&auth).unwrap();
        let decoded: Auth = bincode::deserialize(&encoded).unwrap();
        
        assert_eq!(auth, decoded);
    }

    #[test]
    fn test_ack_serialization() {
        let acks = vec![Ack::Ok, Ack::ServiceNotExist, Ack::AuthFailed];
        
        for ack in acks {
            let encoded = bincode::serialize(&ack).unwrap();
            let decoded: Ack = bincode::deserialize(&encoded).unwrap();
            assert_eq!(ack, decoded);
        }
    }

    #[test]
    fn test_control_channel_cmd_serialization() {
        let cmds = vec![
            ControlChannelCmd::CreateDataChannel,
            ControlChannelCmd::Heartbeat,
        ];
        
        for cmd in cmds {
            let encoded = bincode::serialize(&cmd).unwrap();
            let decoded: ControlChannelCmd = bincode::deserialize(&encoded).unwrap();
            assert_eq!(cmd, decoded);
        }
    }

    #[test]
    fn test_data_channel_cmd_serialization() {
        let cmds = vec![
            DataChannelCmd::StartForwardTcp,
            DataChannelCmd::StartForwardUdp,
        ];
        
        for cmd in cmds {
            let encoded = bincode::serialize(&cmd).unwrap();
            let decoded: DataChannelCmd = bincode::deserialize(&encoded).unwrap();
            assert_eq!(cmd, decoded);
        }
    }

    #[test]
    fn test_udp_traffic_serialization() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use bytes::Bytes;
        
        let traffic = UdpTraffic {
            from: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            data: Bytes::from("test data"),
        };
        
        let encoded = bincode::serialize(&traffic).unwrap();
        let decoded: UdpTraffic = bincode::deserialize(&encoded).unwrap();
        
        assert_eq!(traffic.from, decoded.from);
        assert_eq!(traffic.data, decoded.data);
    }
}
```

运行测试（应该失败）：
```bash
cargo test --package quichole-shr
```

#### 🟢 绿：实现代码

在 `shr/src/protocol/message.rs` 中实现：

```rust
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// 协议版本
pub const PROTO_V1: u8 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Hello {
    ControlChannelHello {
        version: u8,
        service_digest: [u8; 32],
    },
    DataChannelHello {
        version: u8,
        session_key: [u8; 32],
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Auth {
    pub digest: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Ack {
    Ok,
    ServiceNotExist,
    AuthFailed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ControlChannelCmd {
    CreateDataChannel,
    Heartbeat,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DataChannelCmd {
    StartForwardTcp,
    StartForwardUdp,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpTraffic {
    pub from: SocketAddr,
    pub data: Bytes,
}
```

创建 `shr/src/protocol/mod.rs`：

```rust
mod message;

pub use message::*;
```

更新 `shr/src/lib.rs`：

```rust
pub mod protocol;
```

运行测试（应该通过）：
```bash
cargo test --package quichole-shr
```

#### 🔵 重构：优化代码

- 添加文档注释
- 提取常量
- 优化结构

### Step 1.2: 编解码器

#### 🔴 红：写测试

创建 `shr/src/protocol/codec.rs`：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        
        let auth = Auth {
            digest: [1u8; 32],
        };
        
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
    async fn test_read_message_with_invalid_length() {
        let mut buffer = Vec::new();
        buffer.write_u32(u32::MAX).await.unwrap(); // 无效的长度
        
        let mut cursor = std::io::Cursor::new(buffer);
        let result: Result<Hello> = read_message(&mut cursor).await;
        
        assert!(result.is_err());
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
}
```

#### 🟢 绿：实现代码

在 `shr/src/protocol/codec.rs` 中实现：

```rust
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 最大消息大小 (1MB)
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

/// 写入消息到流
pub async fn write_message<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWriteExt + Unpin,
{
    let payload = bincode::serialize(msg)
        .context("Failed to serialize message")?;
    
    let len = payload.len() as u32;
    
    writer.write_u32(len).await
        .context("Failed to write message length")?;
    
    writer.write_all(&payload).await
        .context("Failed to write message payload")?;
    
    writer.flush().await
        .context("Failed to flush writer")?;
    
    Ok(())
}

/// 从流读取消息
pub async fn read_message<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncReadExt + Unpin,
{
    let len = reader.read_u32().await
        .context("Failed to read message length")?;
    
    if len > MAX_MESSAGE_SIZE {
        anyhow::bail!("Message too large: {} bytes", len);
    }
    
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await
        .context("Failed to read message payload")?;
    
    let msg = bincode::deserialize(&payload)
        .context("Failed to deserialize message")?;
    
    Ok(msg)
}
```

更新 `shr/src/protocol/mod.rs`：

```rust
mod message;
mod codec;

pub use message::*;
pub use codec::*;
```

运行测试：
```bash
cargo test --package quichole-shr
```

#### 🔵 重构：优化代码

### Step 1.3: 摘要计算

#### 🔴 红：写测试

创建 `shr/src/protocol/digest.rs`：

```rust
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
        
        // 两次生成的 nonce 应该不同
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_generate_session_key() {
        let key1 = generate_session_key();
        let key2 = generate_session_key();
        
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        
        // 两次生成的 session key 应该不同
        assert_ne!(key1, key2);
    }
}
```

#### 🟢 绿：实现代码

在 `shr/src/protocol/digest.rs` 中实现：

```rust
use sha2::{Digest, Sha256};

/// 计算服务名的摘要
pub fn service_digest(service_name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(service_name.as_bytes());
    hasher.finalize().into()
}

/// 计算认证摘要
pub fn auth_digest(token: &str, nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.update(nonce);
    hasher.finalize().into()
}

/// 生成随机 nonce
pub fn generate_nonce() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};
    
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce).expect("Failed to generate nonce");
    nonce
}

/// 生成随机 session key
pub fn generate_session_key() -> [u8; 32] {
    generate_nonce()
}
```

更新 `shr/Cargo.toml` 添加依赖：

```toml
[dependencies]
sha2 = "0.10"
```

更新 `shr/src/protocol/mod.rs`：

```rust
mod message;
mod codec;
mod digest;

pub use message::*;
pub use codec::*;
pub use digest::*;
```

运行测试：
```bash
cargo test --package quichole-shr
```

## Phase 2: 配置模块

### Step 2.1: 配置结构定义

#### 🔴 红：写测试

创建 `shr/src/config/server.rs`（注意：当前实现使用**顶层字段**格式，不包含 `[server]` 外层表）：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_parsing() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            heartbeat_interval = 30

            [services.ssh]
            token = "secret_token"
            bind_addr = "0.0.0.0:2222"
            type = "tcp"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        
        assert_eq!(config.bind_addr, "0.0.0.0:4433");
        assert_eq!(config.heartbeat_interval, 30);
        assert_eq!(config.services.len(), 1);
        
        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "secret_token");
        assert_eq!(ssh_service.bind_addr, "0.0.0.0:2222");
        assert_eq!(ssh_service.service_type, ServiceType::Tcp);
    }

    #[test]
    fn test_server_config_with_default_token() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        
        assert_eq!(config.default_token, Some("default_secret".to_string()));
        
        let ssh_service = config.services.get("ssh").unwrap();
        // token 应该为空，等待验证时填充
        assert_eq!(ssh_service.token, "");
    }
}
```

#### 🟢 绿：实现代码

在 `shr/src/config/server.rs` 中实现：

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::ServiceType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: String,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: u64,
    #[serde(default)]
    pub default_token: Option<String>,
    pub services: HashMap<String, ServerServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerServiceConfig {
    pub bind_addr: String,
    #[serde(default)]
    pub token: String,
    #[serde(default, rename = "type")]
    pub service_type: ServiceType,
}

fn default_heartbeat_interval() -> u64 {
    30
}

```

创建类似的客户端配置测试和实现（`shr/src/config/client.rs`）：

- `ClientConfig { remote_addr, heartbeat_timeout(默认40), retry_interval(默认1), default_token, services }`
- `ClientServiceConfig { local_addr, token(默认空), type(默认tcp), retry_interval(可选覆盖) }`

并抽取通用枚举到 `shr/src/config/common.rs`：

- `ServiceType::{Tcp,Udp}`（默认 TCP）

> 注意：`toml` crate 不支持将 enum 直接序列化成顶层裸字符串（例如 `"tcp"`），测试时需要用 wrapper struct 作为字段序列化/反序列化。

### Step 2.2: 配置验证

#### 🔴 红：写测试

在 `shr/src/config/server.rs` 增加验证相关测试（示例）：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_validation_fill_default_token() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        config.validate().unwrap();

        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "default_secret");
    }

    #[test]
    fn test_server_config_validation_missing_token() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }
}
```

在 `shr/src/config/client.rs` 增加验证相关测试（示例）：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_validation_fill_default_token() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            default_token = "default_secret"

            [services.ssh]
            local_addr = "127.0.0.1:22"
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        config.validate().unwrap();

        let ssh_service = config.services.get("ssh").unwrap();
        assert_eq!(ssh_service.token, "default_secret");
    }

    #[test]
    fn test_client_config_validation_missing_token() {
        let toml_str = r#"
            remote_addr = "example.com:4433"

            [services.ssh]
            local_addr = "127.0.0.1:22"
        "#;

        let mut config: ClientConfig = toml::from_str(toml_str).unwrap();
        let result = config.validate();

        assert!(result.is_err());
    }
}
```

> 其他校验项（空地址、空 services、超时/重试为 0、服务级 retry_interval 为 0 等）参考对应测试文件。

#### 🟢 绿：实现代码

在 `shr/src/config/server.rs` 中实现 `validate()`：

```rust
use anyhow::{bail, Result};

impl ServerConfig {
    pub fn validate(&mut self) -> Result<()> {
        if self.bind_addr.trim().is_empty() {
            bail!("server bind_addr is empty");
        }
        if self.heartbeat_interval == 0 {
            bail!("server heartbeat_interval must be > 0");
        }
        if self.services.is_empty() {
            bail!("server services is empty");
        }

        let default_token = self
            .default_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .map(str::to_string);

        for (name, service) in &mut self.services {
            if service.bind_addr.trim().is_empty() {
                bail!("server service '{}' bind_addr is empty", name);
            }
            if service.token.is_empty() {
                if let Some(token) = &default_token {
                    service.token = token.clone();
                } else {
                    bail!("server service '{}' token is empty and no default_token", name);
                }
            }
        }

        Ok(())
    }
}
```

在 `shr/src/config/client.rs` 中实现 `validate()`：

```rust
use anyhow::{bail, Result};

impl ClientConfig {
    pub fn validate(&mut self) -> Result<()> {
        if self.remote_addr.trim().is_empty() {
            bail!("client remote_addr is empty");
        }
        if self.heartbeat_timeout == 0 {
            bail!("client heartbeat_timeout must be > 0");
        }
        if self.retry_interval == 0 {
            bail!("client retry_interval must be > 0");
        }
        if self.services.is_empty() {
            bail!("client services is empty");
        }

        let default_token = self
            .default_token
            .as_deref()
            .filter(|token| !token.is_empty())
            .map(str::to_string);

        for (name, service) in &mut self.services {
            if service.local_addr.trim().is_empty() {
                bail!("client service '{}' local_addr is empty", name);
            }
            if let Some(retry_interval) = service.retry_interval {
                if retry_interval == 0 {
                    bail!("client service '{}' retry_interval must be > 0", name);
                }
            }
            if service.token.is_empty() {
                if let Some(token) = &default_token {
                    service.token = token.clone();
                } else {
                    bail!("client service '{}' token is empty and no default_token", name);
                }
            }
        }

        Ok(())
    }
}
```

> 运行测试：`cargo test --package quichole-shr`

## Phase 3: 加密模块

### Step 3.1: Token 认证（常量时间校验）

#### 🔴 红：写测试

在 `shr/src/crypto/token.rs` 添加测试：

```rust
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
}
```

#### 🟢 绿：实现代码

```rust
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

pub fn compute_auth_digest(token: &str, nonce: &[u8; 32]) -> [u8; 32] {
    auth_digest(token, nonce)
}

pub fn verify_auth_digest(client_digest: &[u8; 32], token: &str, nonce: &[u8; 32]) -> bool {
    let expected = auth_digest(token, nonce);
    constant_time_eq(client_digest, &expected)
}
```

#### 🔵 重构

- 保持与协议摘要逻辑复用，避免重复实现
- 使用常量时间对比降低时序攻击风险

## Phase 4: QUIC 基础

### Step 4.1: 流 ID 规则

#### 🔴 红：写测试

在 `shr/src/quic/stream.rs` 添加测试：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_bidi_stream_id() {
        assert_eq!(client_bidi_stream_id(0), 4);
        assert_eq!(client_bidi_stream_id(1), 8);
        assert_eq!(client_bidi_stream_id(2), 12);
    }
}
```

#### 🟢 绿：实现代码

```rust
pub const CONTROL_STREAM_ID: u64 = 0;
pub const CLIENT_BIDI_STREAM_BASE: u64 = 4;

pub const fn client_bidi_stream_id(index: u64) -> u64 {
    CLIENT_BIDI_STREAM_BASE * (index + 1)
}
```

#### 🔵 重构

- 增加 `is_client_bidi_stream_id` / `data_stream_index_from_id` 等辅助函数

### Step 4.2: 连接状态（数据流分配）

#### 🔴 红：写测试

在 `shr/src/quic/connection.rs` 添加测试：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_allocates_stream_ids() {
        let mut state = QuicConnectionState::new(ConnectionRole::Client);

        assert_eq!(state.next_data_stream_id().unwrap(), 4);
        assert_eq!(state.next_data_stream_id().unwrap(), 8);
    }
}
```

#### 🟢 绿：实现代码

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    Client,
    Server,
}

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

    pub fn next_data_stream_id(&mut self) -> Result<u64> {
        if self.role != ConnectionRole::Client {
            bail!("only client can allocate data stream id");
        }

        let id = client_bidi_stream_id(self.next_data_stream_index);
        self.next_data_stream_index += 1;
        Ok(id)
    }
}
```

## Phase 5: 服务端实现

### Step 5.1: 服务注册与摘要索引（MVP）

#### 🔴 红：写测试

在 `svr/src/server.rs` 添加测试：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use quichole_shr::protocol::service_digest;

    #[test]
    fn test_server_state_builds_services() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"

            [services.http]
            bind_addr = "0.0.0.0:8080"
            token = "http_token"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        let server = ServerState::from_config(config).unwrap();

        assert_eq!(server.services_len(), 2);
        let ssh = server.service("ssh").unwrap();
        assert_eq!(ssh.token(), "default_secret");
        let http = server.service("http").unwrap();
        assert_eq!(http.token(), "http_token");
    }

    #[test]
    fn test_server_state_lookup_by_digest() {
        let toml_str = r#"
            bind_addr = "0.0.0.0:4433"
            default_token = "default_secret"

            [services.ssh]
            bind_addr = "0.0.0.0:2222"
        "#;

        let config: ServerConfig = toml::from_str(toml_str).unwrap();
        let server = ServerState::from_config(config).unwrap();

        let digest = service_digest("ssh");
        let service = server.service_by_digest(&digest).unwrap();
        assert_eq!(service.name(), "ssh");
    }
}
```

#### 🟢 绿：实现代码

`ServerState::from_config` 校验配置并建立服务与摘要索引，`Service` 负责封装服务元信息：

```rust
pub struct ServerState { /* ... */ }

impl ServerState {
    pub fn from_config(mut config: ServerConfig) -> Result<Self> {
        config.validate()?;
        // 构建 service 与 digest 索引
        Ok(Self { /* ... */ })
    }
}
```

#### 🔵 重构

- 将服务封装为 `Service`，统一生成 digest
- 增加 `service_by_digest` 以支持握手阶段快速查找

### Step 5.2: 控制通道握手（Hello/Auth/Ack）

#### 🔴 红：写测试

在 `svr/src/handshake.rs` 添加测试覆盖：

- 版本不匹配返回错误
- 服务不存在返回错误
- 认证失败返回错误
- 成功握手后进入会话状态

#### 🟢 绿：实现代码

实现控制通道握手流程：

```rust
pub struct ControlHandshake { /* service + nonce */ }

pub fn begin_control_handshake(server: &ServerState, hello: &Hello) -> Result<ControlHandshake> {
    // 校验版本 -> 根据 service_digest 找服务 -> 生成 nonce
}

impl ControlHandshake {
    pub fn verify_auth(self, auth: &Auth) -> Result<ControlSession> {
        // verify_auth_digest(token, nonce)
    }
}
```

#### 🔵 重构

- 将 nonce 与服务绑定到 `ControlHandshake`
- 认证通过后返回 `ControlSession`

### Step 5.3: 数据通道创建请求/路由

#### 🔴 红：写测试

在 `svr/src/handshake.rs` 添加测试覆盖：

- 创建数据通道后，下发 `CreateDataChannel`
- DataChannelHello 匹配 session_key
- TCP/UDP 分别返回 `StartForwardTcp` / `StartForwardUdp`

#### 🟢 绿：实现代码

```rust
impl ControlSession {
    pub fn create_data_channel(&mut self) -> (ControlChannelCmd, [u8; 32]) {
        // 生成 session_key，并记录期望的 ServiceType
    }

    pub fn accept_data_channel_hello(&mut self, hello: &Hello) -> Result<DataChannelCmd> {
        // 校验版本 + session_key -> 返回 StartForwardTcp/Udp
    }
}
```

#### 🔵 重构

- 抽出 `DataChannelManager` 维护 pending session_key
- 将 ServiceType 映射逻辑集中处理

### Step 5.4: tokio-quiche 运行时与控制通道接入

#### 🔴 红：新增帧解码与 QUIC 适配测试

- 在 `shr/src/protocol/codec.rs` 新增帧解码器 `FrameDecoder`
- 测试覆盖：分段输入、多消息解码、超长帧错误

#### 🟢 绿：实现 QUIC 适配层

- 新增 `shr/src/quic/app.rs`：
  - `QuicApp`：实现 `ApplicationOverQuic`
  - `QuicStreamHandle`：基于 channel 的流读写
  - `StreamChunk`：携带 `fin`

#### 🔵 重构

- 统一使用长度前缀帧发送 `nonce` / `session_key`
- 将控制通道与数据通道的 framing 逻辑复用

### Step 5.5: 服务端实际收发（控制通道 + 数据通道）

#### 🟢 绿：实现服务端运行时

- 新增 `svr/src/runtime.rs`：
  - tokio-quiche 监听 UDP/QUIC
  - 控制通道握手（Hello/Auth/Ack）
  - `CreateDataChannel` + `session_key` 下发
  - TCP/UDP 转发（MVP）

#### 🔵 重构

- 控制通道与数据通道拆分任务
- 以 `ControlRequest` 串行化 `CreateDataChannel` 请求

## Phase 6-7: 后续阶段

### Phase 6: 客户端实现

#### Step 6.1: 客户端服务注册（MVP）

#### 🔴 红：写测试

在 `cli/src/client.rs` 添加测试：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_state_builds_services() {
        let toml_str = r#"
            remote_addr = "example.com:4433"
            default_token = "default_secret"

            [services.ssh]
            local_addr = "127.0.0.1:22"
        "#;

        let config: ClientConfig = toml::from_str(toml_str).unwrap();
        let client = ClientState::from_config(config).unwrap();

        assert_eq!(client.services_len(), 1);
    }
}
```

#### 🟢 绿：实现代码

`ClientState::from_config` 校验配置并构建服务列表：

```rust
pub struct ClientState { /* ... */ }

impl ClientState {
    pub fn from_config(mut config: ClientConfig) -> Result<Self> {
        config.validate()?;
        // 构建 service map
        Ok(Self { /* ... */ })
    }
}
```

#### Step 6.2: 客户端握手消息

#### 🔴 红：写测试

在 `cli/src/handshake.rs` 添加测试覆盖：

- ControlChannelHello 生成
- Auth digest 生成
- DataChannelHello 生成
- Ack 校验

#### 🟢 绿：实现代码

```rust
pub fn control_hello(service_name: &str) -> Hello { /* ... */ }
pub fn auth_message(token: &str, nonce: &[u8; 32]) -> Auth { /* ... */ }
pub fn data_channel_hello(session_key: [u8; 32]) -> Hello { /* ... */ }
pub fn verify_ack(ack: &Ack) -> Result<()> { /* ... */ }
```

#### 🔵 重构

- 统一使用 `PROTO_V1`
- 复用 `compute_auth_digest`

#### Step 6.3: 客户端实际收发（控制通道 + 数据通道）

#### 🟢 绿：实现客户端运行时

- 新增 `cli/src/runtime.rs`：
  - tokio-quiche 客户端连接
  - 控制通道握手（Hello/Auth/Ack）
  - 响应 `CreateDataChannel`，创建数据流
  - TCP/UDP 转发（MVP）

#### 🔵 重构

- 数据通道转发任务与控制通道解耦
- 为避免数据通道命令与首包数据共帧，解码 `DataChannelCmd` 后将剩余字节交给转发逻辑处理

## Phase 7: 集成测试

后续阶段遵循相同的 TDD 流程：

1. **Phase 7: 集成测试** - 端到端测试

每个阶段都按照：测试 → 实现 → 重构的循环进行。

### Step 7.1: 端到端握手（无网络）

在 `svr/tests/e2e_handshake.rs` 添加跨 crate 集成测试：

```rust
#[test]
fn test_e2e_control_and_data_channel_tcp() {
    let server = build_server();
    let client = build_client();

    let service = client.service("ssh").unwrap();
    let hello = control_hello(service.name());
    let handshake = begin_control_handshake(&server, &hello).unwrap();
    let auth = auth_message(service.token(), handshake.nonce());
    let mut session = handshake.verify_auth(&auth).unwrap();

    let (cmd, session_key) = session.create_data_channel();
    assert_eq!(cmd, ControlChannelCmd::CreateDataChannel);

    let data_hello = data_channel_hello(session_key);
    let data_cmd = session.accept_data_channel_hello(&data_hello).unwrap();
    assert_eq!(data_cmd, DataChannelCmd::StartForwardTcp);
}
```

该测试在不依赖网络的前提下验证控制通道/数据通道握手的完整路径。

## 测试命令

```bash
# 运行所有测试
cargo test

# 运行特定包的测试
cargo test --package quichole-shr

# 运行特定测试
cargo test test_hello_serialization

# 查看测试覆盖率
cargo tarpaulin --out Html

# 运行集成测试
cargo test --test '*'
```

## 持续集成

在 `.github/workflows/ci.yml` 中配置 CI：

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - run: cargo test --all
      - run: cargo clippy -- -D warnings
      - run: cargo fmt -- --check
```

## 总结

通过严格遵循 TDD 流程，我们可以：

- ✅ 确保代码质量
- ✅ 提高测试覆盖率
- ✅ 及早发现问题
- ✅ 便于重构
- ✅ 提供文档化的代码示例

每个 Phase 完成后，进行代码审查，确保代码质量和一致性。
