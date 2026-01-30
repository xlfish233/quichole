# Quichole 架构设计

## 项目结构

```
quichole/
├── Cargo.toml          # Workspace 配置
├── README.md           # 项目说明
├── ARCHITECTURE.md     # 架构文档
├── shr/                # 共享库 (quichole-shr)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── protocol/   # 协议定义
│       │   ├── mod.rs
│       │   ├── message.rs    # 消息类型
│       │   ├── codec.rs      # 消息编解码
│       │   └── digest.rs     # 摘要与随机数
│       ├── config/     # 配置结构与校验
│       │   ├── mod.rs
│       │   ├── common.rs
│       │   ├── server.rs
│       │   └── client.rs
│       ├── quic/       # QUIC 基础
│       │   ├── mod.rs
│       │   ├── connection.rs
│       │   ├── stream.rs
│       │   └── app.rs         # tokio-quiche 适配层
│       └── crypto/     # 加密相关
│           ├── mod.rs
│           └── token.rs      # Token 认证
├── svr/                # 服务端 (quichole-svr)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── server.rs         # 服务端核心逻辑
│       ├── service.rs        # 服务管理
│       ├── handshake.rs      # 控制/数据通道握手
│       └── runtime.rs        # tokio-quiche 运行时
└── cli/                # 客户端 (quichole-cli)
    ├── Cargo.toml
    └── src/
        ├── main.rs
        ├── client.rs         # 客户端核心逻辑
        ├── service.rs        # 服务管理
        ├── handshake.rs      # 客户端握手
        └── runtime.rs        # tokio-quiche 运行时
```

## 核心组件

### 1. 共享库 (shr)

提供客户端和服务端共用的功能：

#### Protocol 模块
- **Message**: 协议消息定义
  - `Hello`: 控制/数据通道 Hello
  - `Auth`: 认证摘要
  - `Ack`: 认证响应
  - `ControlChannelCmd`: 控制通道命令（创建数据通道/心跳）
  - `DataChannelCmd`: 数据通道命令（开始转发 TCP/UDP）
  - `UdpTraffic`: UDP 流量封装
- **Codec**: 长度前缀 + bincode 编解码，支持流式解码与剩余字节保留，避免数据通道命令与首包数据共帧导致丢包
- **Digest**: 服务摘要、nonce、session_key、认证摘要

#### Config 模块
- 服务端配置: 监听地址、心跳间隔、心跳 ACK 超时、默认 token、服务列表（bind_addr/type/token）
- 客户端配置: 服务器地址、心跳超时、重试间隔、默认 token、服务列表（local_addr/type/token/retry_interval）

#### Crypto 模块
- Token 认证摘要计算与校验（常量时间对比）
- TLS 配置结构（已支持私有 CA / mTLS）

### 2. 服务端 (svr)

#### 主要流程

```
1. tokio-quiche 监听 QUIC 端口 (如 4433)
2. 接收控制通道 Hello/Auth/Ack 完成认证
3. 监听服务暴露端口（TCP/UDP）
4. 访问者连接/发包时：
   - 通过控制通道发送 CreateDataChannel + session_key
   - 客户端创建 QUIC 数据流
   - 双向转发数据
```

#### 核心结构

```rust
struct Server {
    config: ServerConfig,
    quic_socket: UdpSocket,
    quic_config: quiche::Config,
    connections: HashMap<ConnectionId, Connection>,
    services: HashMap<String, Service>,
}

struct Service {
    name: String,
    token: String,
    bind_addr: SocketAddr,
    tcp_listener: TcpListener,
    client_conn_id: Option<ConnectionId>,
}
```

### 3. 客户端 (cli)

#### 主要流程

```
1. 连接到服务端 QUIC 端口
2. 发送 Hello/Auth 并等待 Ack
3. 等待服务端 CreateDataChannel 请求
4. 收到请求后：
   - 创建新的 QUIC 数据流
   - 连接到本地服务 (如 127.0.0.1:22)
   - 双向转发数据
```

#### 核心结构

```rust
struct Client {
    config: ClientConfig,
    quic_conn: quiche::Connection,
    services: HashMap<String, ServiceConfig>,
    active_streams: HashMap<u64, TcpStream>,
}
```

## 协议设计

### 消息帧格式

所有控制/数据通道消息在 QUIC 流中的帧格式为长度前缀 + bincode 负载：

```
+------------------+------------------+
|  Length (4 bytes)|  Payload         |
|  (big-endian)    |  (bincode)       |
+------------------+------------------+
```

详细定义请参考 `docs/PROTOCOL.md`。

### 数据流

- Stream 0: 控制流（双向）
- Stream 4, 8, 12, ...: 客户端发起的数据流（双向）
- 每个数据流对应一个访问者连接（TCP/UDP）

## 参考 rathole 的设计

### 相似之处
1. 服务级别的 token 认证
2. 控制通道 + 数据通道分离
3. 配置文件格式

### 不同之处
1. 传输协议: QUIC vs TCP/TLS
2. 多路复用: QUIC 原生支持 vs 需要多个 TCP 连接
3. 连接恢复: QUIC 0-RTT vs TCP 重连

## 协议详细设计

### 协议版本

```rust
const PROTO_V1: u8 = 1;
```

协议版本用于确保客户端和服务端的兼容性。如果版本不匹配，连接将被拒绝。

### 消息类型定义

所有控制消息通过 QUIC Stream 0 发送，使用 bincode 进行二进制序列化。

#### Hello 消息

用于初始化控制通道和数据通道：

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum Hello {
    /// 控制通道 Hello，包含协议版本和服务摘要
    ControlChannelHello {
        version: u8,
        service_digest: [u8; 32], // SHA-256(service_name)
    },
    /// 数据通道 Hello，包含协议版本和会话密钥
    DataChannelHello {
        version: u8,
        session_key: [u8; 32], // 服务端生成的随机密钥
    },
}
```

#### Auth 消息

客户端发送认证信息：

```rust
#[derive(Serialize, Deserialize, Debug)]
pub struct Auth {
    pub digest: [u8; 32], // SHA-256(token + nonce)
}
```

#### Ack 消息

服务端响应客户端请求：

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum Ack {
    Ok,
    ServiceNotExist,
    AuthFailed,
}
```

#### 控制通道命令

服务端通过控制通道发送的命令：

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum ControlChannelCmd {
    CreateDataChannel,  // 请求客户端创建新的数据通道
    Heartbeat,          // 心跳消息
}
```

#### 数据通道命令

服务端通过数据通道发送的命令：

```rust
#[derive(Serialize, Deserialize, Debug)]
pub enum DataChannelCmd {
    StartForwardTcp,  // 开始 TCP 转发
    StartForwardUdp,  // 开始 UDP 转发
}
```

#### UDP 流量封装

UDP 数据包需要携带源地址信息：

```rust
#[derive(Serialize, Deserialize, Debug)]
pub struct UdpTraffic {
    pub from: SocketAddr,  // 源地址
    pub data: Bytes,       // UDP 数据
}
```

### 控制通道详细流程

#### 1. 控制通道建立

```
客户端                                    服务端
  |                                         |
  |-- ControlChannelHello(v1, digest) ---->|
  |                                         | 验证服务是否存在
  |<---------- nonce (32 bytes) -----------|
  |                                         |
  | 计算 auth = SHA-256(token + nonce)      |
  |                                         |
  |------------ Auth(auth) ---------------->|
  |                                         | 验证 auth
  |<------------ Ack::Ok -------------------|
  |                                         |
  |      控制通道建立成功                    |
```

#### 2. 心跳机制

- 服务端每隔 `heartbeat_interval` 秒发送 `Heartbeat` 命令
- 客户端收到心跳后回发 `Heartbeat` 作为 ACK
- 服务端若在 `heartbeat_ack_timeout` 内未收到 ACK，认为连接断开（默认 `heartbeat_interval * 3`）
- 客户端在 `heartbeat_timeout` 秒内未收到心跳，认为连接断开
- 客户端将尝试重新连接
- 控制通道关闭时，服务端停止对应服务监听，避免端口占用导致重连失败

#### 3. 数据通道创建请求

```
访问者                服务端                    客户端
  |                     |                         |
  |-- TCP 连接 -------->|                         |
  |                     |                         |
  |                     |-- CreateDataChannel --->|
  |                     |                         |
  |                     |<-- 新 QUIC 流 ----------|
  |                     |                         |
  |                     |<-- DataChannelHello ----|
  |                     |                         |
  |                     |-- StartForwardTcp ----->|
  |                     |                         |
  |                     |                         |-- 连接本地服务
  |                     |                         |
  |<-- 开始转发数据 --->|<----- 双向转发 -------->|
```

### 数据通道详细流程

#### TCP 数据转发

1. 访问者连接到服务端的暴露端口
2. 服务端通过控制通道请求客户端创建数据通道
3. 客户端创建新的 QUIC 流（Stream ID: 4, 8, 12...）
4. 客户端发送 `DataChannelHello` 携带 session_key
5. 服务端验证 session_key 并发送 `StartForwardTcp`
6. 客户端连接到本地 TCP 服务
7. 双向复制数据：访问者 <-> 服务端 <-> 客户端 <-> 本地服务

#### UDP 数据转发

1. 访问者发送 UDP 数据包到服务端的暴露端口
2. 服务端通过控制通道请求客户端创建数据通道
3. 客户端创建新的 QUIC 流用于 UDP 转发
4. 服务端将 UDP 数据包封装为 `UdpTraffic` 发送到客户端
5. 客户端解封装后发送到本地 UDP 服务
6. 本地服务的响应按相反路径返回

### QUIC 流 ID 分配

- **Stream 0**: 控制流（双向）
  - 用于认证、心跳、数据通道创建请求
- **Stream 4, 8, 12, ...**: 数据流（双向，客户端发起）
  - 每个数据流对应一个访问者连接
  - 流 ID 必须是 4 的倍数（QUIC 客户端发起的双向流）

### QUIC 特性利用

#### 1. 多路复用

- 单个 QUIC 连接可以承载多个服务的数据流
- 不同服务的流之间相互独立，无队头阻塞
- 减少连接建立开销

#### 2. 0-RTT 连接恢复

- 客户端可以缓存服务端的配置
- 重连时可以在 0-RTT 内恢复连接
- 减少重连延迟

#### 3. 连接迁移

- 客户端 IP 地址变化时（如移动网络切换）
- QUIC 连接可以无缝迁移，不中断服务
- 通过 Connection ID 识别连接

#### 4. 流量控制

- QUIC 内置流级别和连接级别的流量控制
- 防止快速发送方压垮慢速接收方
- 自动调整发送速率

#### 5. 拥塞控制

- QUIC 实现了现代拥塞控制算法
- 比 TCP 更快地适应网络条件变化
- 提高带宽利用率

## 错误处理

### 协议错误

- **版本不匹配**: 返回错误并关闭连接
- **认证失败**: 返回 `Ack::AuthFailed` 并关闭连接
- **服务不存在**: 返回 `Ack::ServiceNotExist` 并关闭连接

### 网络错误

- **连接超时**: 客户端使用指数退避重连
- **流关闭**: 清理相关资源，通知对端
- **数据包丢失**: QUIC 自动重传

### 应用错误

- **本地服务不可达**: 关闭数据通道，记录错误
- **配置错误**: 启动时验证并拒绝启动
- **资源耗尽**: 限制并发连接数，拒绝新连接

## TDD 实施计划

详细的 TDD 实施步骤请参考 [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)。

### 开发阶段

1. **Phase 1**: 协议模块（消息定义、编解码、摘要）
2. **Phase 2**: 配置模块（配置解析、验证）
3. **Phase 3**: 加密模块（Token 认证）
4. **Phase 4**: QUIC 基础（连接管理、流管理）
5. **Phase 5**: 服务端实现（启动、控制通道、数据通道）
6. **Phase 6**: 客户端实现（启动、控制通道、数据通道）
7. **Phase 7**: 集成测试（端到端测试、错误场景）

### TDD 原则

- ✅ 先写测试，后写实现
- ✅ 测试覆盖率 >80%
- ✅ 小步前进，频繁提交
- ✅ 每个 Phase 完成后代码审查
- ✅ 持续集成，所有测试通过

## 相关文档

- [协议规范](docs/PROTOCOL.md) - 详细的协议定义和消息格式
- [实现指南](docs/IMPLEMENTATION.md) - TDD 实施步骤和代码示例
- [与 rathole 对比](docs/COMPARISON.md) - 架构和性能对比
- [配置文档](docs/CONFIGURATION.md) - 配置选项与校验规则
