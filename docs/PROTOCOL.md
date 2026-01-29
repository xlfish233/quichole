# Quichole 协议规范

本文档详细定义了 quichole 客户端和服务端之间的通信协议。

## 目录

- [协议版本](#协议版本)
- [消息类型](#消息类型)
- [控制通道协议](#控制通道协议)
- [数据通道协议](#数据通道协议)
- [序列化格式](#序列化格式)
- [错误处理](#错误处理)

## 协议版本

```rust
/// 协议版本 1
pub const PROTO_V1: u8 = 1;

/// 当前使用的协议版本
pub const CURRENT_PROTO_VERSION: u8 = PROTO_V1;
```

协议版本用于确保客户端和服务端的兼容性。每个消息都包含版本号，如果版本不匹配，连接将被拒绝。

## 消息类型

### Hello 消息

Hello 消息用于初始化控制通道和数据通道。

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Hello {
    /// 控制通道 Hello
    /// 
    /// 客户端发送此消息以建立控制通道
    ControlChannelHello {
        /// 协议版本
        version: u8,
        /// 服务摘要 (SHA-256(service_name))
        service_digest: [u8; 32],
    },
    
    /// 数据通道 Hello
    /// 
    /// 客户端发送此消息以建立数据通道
    DataChannelHello {
        /// 协议版本
        version: u8,
        /// 会话密钥（服务端生成）
        session_key: [u8; 32],
    },
}
```

### Auth 消息

Auth 消息用于客户端认证。

```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Auth {
    /// 认证摘要 (SHA-256(token + nonce))
    pub digest: [u8; 32],
}
```

### Ack 消息

Ack 消息是服务端对客户端请求的响应。

```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Ack {
    /// 认证成功
    Ok,
    /// 服务不存在
    ServiceNotExist,
    /// 认证失败
    AuthFailed,
}
```

### 控制通道命令

服务端通过控制通道发送的命令。

```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ControlChannelCmd {
    /// 请求客户端创建新的数据通道
    CreateDataChannel,
    /// 心跳消息
    Heartbeat,
}
```

### 数据通道命令

服务端通过数据通道发送的命令。

```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DataChannelCmd {
    /// 开始 TCP 转发
    StartForwardTcp,
    /// 开始 UDP 转发
    StartForwardUdp,
}
```

### UDP 流量封装

UDP 数据包需要携带源地址信息。

```rust
use bytes::Bytes;
use std::net::SocketAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpTraffic {
    /// 源地址
    pub from: SocketAddr,
    /// UDP 数据
    pub data: Bytes,
}
```

## 摘要与随机数

协议中使用 SHA-256（32 字节输出）进行服务标识与认证摘要计算。

### 服务摘要

- `service_digest = SHA-256(service_name)`
- 用于 `Hello::ControlChannelHello` 的 `service_digest`

### 认证摘要

- `auth_digest = SHA-256(token + nonce)`
- 客户端收到服务端 `nonce` 后计算并发送 `Auth { digest }`

### Nonce / Session Key

- `nonce`: 32 字节随机挑战值，用于防重放
- `session_key`: 32 字节随机值，用于数据通道关联（在 quichole 中由服务端生成并校验）

### 参考实现（shr）

实际实现位于：

- `shr/src/protocol/digest.rs`
- `shr/src/protocol/message.rs`（`PROTO_V1`、`Hello` 等）
```

## 控制通道协议

控制通道使用 QUIC Stream 0（双向流）进行通信。

### 建立流程

```
客户端                                    服务端
  |                                         |
  |-- ControlChannelHello(v1, digest) ---->|
  |                                         |
  |                                         | 1. 验证协议版本
  |                                         | 2. 查找服务
  |                                         | 3. 生成 nonce
  |                                         |
  |<---- nonce (32 bytes, framed) --------|
  |                                         |
  | 计算 auth = SHA-256(token + nonce)      |
  |                                         |
  |------------ Auth(auth) ---------------->|
  |                                         |
  |                                         | 验证 auth
  |                                         |
  |<------------ Ack::Ok -------------------|
  |                                         |
  |      控制通道建立成功                    |
  |                                         |
  |<-------- Heartbeat (定期) --------------|
  |                                         |
  |<---- CreateDataChannel (按需) ---------|
```

### 认证流程详解

1. **客户端发送 ControlChannelHello**
   - 包含协议版本和服务摘要
   - 服务摘要 = SHA-256(service_name)

2. **服务端验证并发送 nonce**
   - 检查协议版本是否匹配
   - 查找服务是否存在
   - 生成 32 字节随机 nonce
   - 发送 nonce 给客户端（使用长度前缀帧编码）

3. **客户端计算并发送 Auth**
   - 计算 auth = SHA-256(token + nonce)
   - 发送 Auth 消息

4. **服务端验证 Auth**
   - 计算期望的 auth = SHA-256(token + nonce)
   - 比较客户端发送的 auth
   - 发送 Ack::Ok 或 Ack::AuthFailed

### 心跳机制

- 服务端每隔 `heartbeat_interval` 秒发送 `Heartbeat` 命令
- 客户端收到心跳后更新最后接收时间
- 如果客户端在 `heartbeat_timeout` 秒内未收到心跳，认为连接断开
- 客户端将使用指数退避策略重新连接

### 数据通道创建请求

当访问者连接到服务端的暴露端口时：

1. 服务端通过控制通道发送 `CreateDataChannel` 命令
2. 服务端紧接着发送 `session_key`（32 字节，使用同样的长度前缀帧编码）
3. 客户端收到命令后创建新的 QUIC 流
4. 客户端通过新流发送 `DataChannelHello`
5. 服务端验证 session_key 并发送 `StartForwardTcp` 或 `StartForwardUdp`

## 数据通道协议

数据通道使用 QUIC Stream 4, 8, 12, ... （客户端发起的双向流）进行通信。

### TCP 转发流程

```
访问者                服务端                    客户端                本地服务
  |                     |                         |                      |
  |-- TCP 连接 -------->|                         |                      |
  |                     |                         |                      |
  |                     |-- CreateDataChannel --->|                      |
  |                     |   (通过控制通道)         |                      |
  |                     |-- session_key -------->|                      |
  |                     |   (控制通道)            |                      |
  |                     |                         |                      |
  |                     |<-- 新 QUIC 流 ----------|                      |
  |                     |                         |                      |
  |                     |<- DataChannelHello -----|                      |
  |                     |   (session_key)         |                      |
  |                     |                         |                      |
  |                     |-- StartForwardTcp ----->|                      |
  |                     |                         |                      |
  |                     |                         |-- TCP 连接 --------->|
  |                     |                         |                      |
  |<-- 数据 ----------->|<----- 数据 ------------>|<----- 数据 -------->|
  |                     |                         |                      |
```

### UDP 转发流程

```
访问者                服务端                    客户端                本地服务
  |                     |                         |                      |
  |-- UDP 数据包 ------>|                         |                      |
  |                     |                         |                      |
  |                     |-- CreateDataChannel --->|                      |
  |                     |   (通过控制通道)         |                      |
  |                     |-- session_key -------->|                      |
  |                     |   (控制通道)            |                      |
  |                     |                         |                      |
  |                     |<-- 新 QUIC 流 ----------|                      |
  |                     |                         |                      |
  |                     |<- DataChannelHello -----|                      |
  |                     |   (session_key)         |                      |
  |                     |                         |                      |
  |                     |-- StartForwardUdp ----->|                      |
  |                     |                         |                      |
  |                     |-- UdpTraffic ---------->|                      |
  |                     |   {from, data}          |-- UDP 数据包 ------->|
  |                     |                         |                      |
  |                     |                         |<-- UDP 数据包 -------|
  |                     |<-- UdpTraffic ----------|                      |
  |<-- UDP 数据包 ------|   {from, data}          |                      |
  |                     |                         |                      |
```

### QUIC 流 ID 分配

- **Stream 0**: 控制流（双向）
  - 用于认证、心跳、数据通道创建请求
  
- **Stream 4, 8, 12, ...**: 数据流（双向，客户端发起）
  - 每个数据流对应一个访问者连接
  - 流 ID 必须是 4 的倍数（QUIC 规范：客户端发起的双向流）
  - 流 ID = 4 * (n + 1)，其中 n = 0, 1, 2, ...

## 序列化格式

所有消息使用 [bincode](https://github.com/bincode-org/bincode) 进行二进制序列化。

### 编码示例

```rust
use bincode;

// 编码
let hello = Hello::ControlChannelHello {
    version: PROTO_V1,
    service_digest: [0u8; 32],
};
let encoded: Vec<u8> = bincode::serialize(&hello)?;

// 解码
let decoded: Hello = bincode::deserialize(&encoded)?;
```

### 消息帧格式

每个消息在 QUIC 流中的格式：

```
+------------------+------------------+
|  Length (4 bytes)|  Payload         |
|  (big-endian)    |  (bincode)       |
+------------------+------------------+
```

> `nonce` 与 `session_key` 也使用同样的帧格式进行编码（payload 为 `[u8; 32]` 的 bincode 结果）。

- **Length**: 消息负载的长度（不包括长度字段本身）
- **Payload**: bincode 序列化的消息

### 读写辅助函数

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use anyhow::Result;

/// 写入消息到流
pub async fn write_message<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWriteExt + Unpin,
{
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    
    writer.write_u32(len).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    
    Ok(())
}

/// 从流读取消息
pub async fn read_message<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncReadExt + Unpin,
{
    let len = reader.read_u32().await? as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    
    let msg = bincode::deserialize(&payload)?;
    Ok(msg)
}
```

## 错误处理

### 协议错误

| 错误类型 | 处理方式 |
|---------|---------|
| 版本不匹配 | 服务端关闭连接，客户端记录错误并退出 |
| 服务不存在 | 服务端返回 `Ack::ServiceNotExist`，客户端记录错误并退出 |
| 认证失败 | 服务端返回 `Ack::AuthFailed`，客户端记录错误并退出 |
| 消息格式错误 | 关闭相关流或连接，记录错误 |

### 网络错误

| 错误类型 | 处理方式 |
|---------|---------|
| 连接超时 | 客户端使用指数退避重连 |
| 流关闭 | 清理相关资源，通知对端 |
| 数据包丢失 | QUIC 自动重传 |
| 连接迁移 | QUIC 自动处理 |

### 应用错误

| 错误类型 | 处理方式 |
|---------|---------|
| 本地服务不可达 | 关闭数据通道，记录错误 |
| 配置错误 | 启动时验证并拒绝启动 |
| 资源耗尽 | 限制并发连接数，拒绝新连接 |

## 安全考虑

### 认证安全

1. **Token 保护**
   - Token 不应在网络上明文传输
   - 使用 SHA-256(token + nonce) 进行认证
   - Nonce 确保每次认证都是唯一的

2. **重放攻击防护**
   - 每次连接使用新的 nonce
   - Nonce 由服务端生成，客户端不能预测

3. **服务隔离**
   - 每个服务使用独立的 token
   - 服务之间相互隔离

### 传输安全

1. **QUIC 内置加密**
   - QUIC 使用 TLS 1.3 加密所有数据
   - 提供前向保密性

2. **连接 ID**
   - QUIC 使用 Connection ID 识别连接
   - 防止连接劫持

## 扩展性

### 未来版本

协议设计考虑了未来的扩展性：

1. **版本协商**
   - 支持多个协议版本共存
   - 客户端和服务端协商使用的版本

2. **新消息类型**
   - 可以添加新的消息类型
   - 旧版本客户端/服务端可以忽略未知消息

3. **可选特性**
   - 通过 Hello 消息协商可选特性
   - 如压缩、加密算法选择等

## 参考

- [QUIC 规范 (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)
- [bincode 文档](https://docs.rs/bincode/)
- [rathole 协议设计](https://github.com/rapiz1/rathole)
