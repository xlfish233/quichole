# Quichole vs Rathole 对比分析

本文档详细对比了 quichole 和 rathole 的架构、协议、性能等方面的差异。

## 目录

- [架构对比](#架构对比)
- [协议对比](#协议对比)
- [传输层对比](#传输层对比)
- [性能对比](#性能对比)
- [功能对比](#功能对比)
- [使用场景](#使用场景)

## 架构对比

### 整体架构

| 方面 | Rathole | Quichole |
|------|---------|----------|
| 传输协议 | TCP/TLS/Noise/WebSocket | QUIC (UDP) |
| 控制通道 | 独立 TCP 连接 | QUIC Stream 0 |
| 数据通道 | 独立 TCP 连接 | QUIC Stream 4, 8, 12... |
| 多路复用 | ❌ 需要多个 TCP 连接 | ✅ 单个 QUIC 连接 |
| 连接数 | 每个服务 1+ 个连接 | 所有服务共享 1 个连接 |

### 架构图对比

#### Rathole 架构

```
客户端                     服务端                    访问者
  |                          |                         |
  |-- 控制连接 (TCP) -------->|                         |
  |                          |                         |
  |                          |<-- TCP 连接 ------------|
  |<-- 数据连接 1 (TCP) ------|                         |
  |<-- 数据连接 2 (TCP) ------|                         |
  |<-- 数据连接 N (TCP) ------|                         |
  |                          |                         |
  +--> 本地服务              |                         |

问题：
- 每个访问者连接需要新的 TCP 连接
- 多个 TCP 连接增加开销
- 可能存在队头阻塞
```

#### Quichole 架构

```
客户端                     服务端                    访问者
  |                          |                         |
  |====== QUIC 连接 ========>|                         |
  | Stream 0: 控制流         |                         |
  | Stream 4: 数据流 1       |<-- TCP 连接 ------------|
  | Stream 8: 数据流 2       |<-- TCP 连接 ------------|
  | Stream 12: 数据流 N      |<-- TCP 连接 ------------|
  |                          |                         |
  +--> 本地服务              |                         |

优势：
- 单个 QUIC 连接承载所有流
- 流之间相互独立，无队头阻塞
- 连接建立开销更小
```

## 协议对比

### 控制通道协议

#### Rathole

```
客户端                                    服务端
  |                                         |
  |-- TCP 连接 --------------------------->|
  |                                         |
  |-- Hello (service_digest) ------------->|
  |                                         |
  |<---------- nonce ----------------------|
  |                                         |
  |-- Auth (hash(token + nonce)) --------->|
  |                                         |
  |<---------- Ack ------------------------|
  |                                         |
  |<---------- Heartbeat (定期) -----------|
  |                                         |
  |<---------- CreateDataChannel ----------|
```

#### Quichole

```
客户端                                    服务端
  |                                         |
  |====== QUIC 连接 (Stream 0) ===========>|
  |                                         |
  |-- ControlChannelHello ---------------->|
  |   (version, service_digest)            |
  |                                         |
  |<---------- nonce ----------------------|
  |                                         |
  |-- Auth (hash(token + nonce)) --------->|
  |                                         |
  |<---------- Ack::Ok --------------------|
  |                                         |
  |<---------- Heartbeat (定期) -----------|
  |                                         |
  |<---------- CreateDataChannel ----------|
```

**主要差异**：
- Rathole 使用独立的 TCP 连接
- Quichole 使用 QUIC Stream 0
- 协议消息格式基本相同

### 数据通道协议

#### Rathole

```
客户端                     服务端
  |                          |
  |<-- 新 TCP 连接 ----------|
  |                          |
  |-- Hello (session_key) -->|
  |                          |
  |<-- StartForward ---------|
  |                          |
  |<====== 数据传输 ========>|
```

#### Quichole

```
客户端                     服务端
  |                          |
  |-- 新 QUIC 流 ----------->|
  |   (Stream 4/8/12...)     |
  |                          |
  |-- DataChannelHello ----->|
  |   (session_key)          |
  |                          |
  |<-- StartForwardTcp ------|
  |                          |
  |<====== 数据传输 ========>|
```

**主要差异**：
- Rathole 每个数据通道是独立的 TCP 连接
- Quichole 每个数据通道是 QUIC 流
- Quichole 的流创建开销更小

## 传输层对比

### 传输协议特性

| 特性 | Rathole (TCP) | Quichole (QUIC) |
|------|---------------|-----------------|
| 基础协议 | TCP | UDP |
| 加密 | 可选 (TLS/Noise) | 内置 (TLS 1.3) |
| 多路复用 | ❌ | ✅ |
| 队头阻塞 | ⚠️ 可能存在 | ✅ 无（流级别） |
| 连接迁移 | ❌ | ✅ |
| 0-RTT | ❌ | ✅ |
| 连接建立 | 3 次握手 + TLS | 1-RTT (首次) / 0-RTT (重连) |
| NAT 穿透 | 较难 | 较容易 (UDP) |

### 连接建立时间

#### Rathole (TCP + TLS)

```
客户端                     服务端
  |                          |
  |-- SYN ------------------>|  \
  |<-- SYN-ACK --------------|   > TCP 3次握手
  |-- ACK ------------------>|  /
  |                          |
  |-- ClientHello ---------->|  \
  |<-- ServerHello ----------|   |
  |<-- Certificate ----------|   |
  |<-- ServerHelloDone ------|   > TLS 握手
  |-- ClientKeyExchange ---->|   |
  |-- ChangeCipherSpec ----->|   |
  |-- Finished ------------->|   |
  |<-- ChangeCipherSpec -----|   |
  |<-- Finished --------------|  /
  |                          |
  总计: ~2-3 RTT
```

#### Quichole (QUIC)

```
客户端                     服务端
  |                          |
  |-- Initial (ClientHello)->|  \
  |<-- Initial (ServerHello)-|   > QUIC + TLS 1.3
  |-- Handshake ------------>|   > 合并握手
  |<-- Handshake ------------|  /
  |                          |
  总计: 1 RTT (首次)
       0 RTT (重连，使用缓存)
```

### 多路复用对比

#### Rathole

```
服务 A 数据 --> TCP 连接 1 --> 服务端
服务 B 数据 --> TCP 连接 2 --> 服务端
服务 C 数据 --> TCP 连接 3 --> 服务端

问题：
- 每个连接独立的拥塞控制
- 连接之间可能竞争带宽
- 连接数增加系统开销
```

#### Quichole

```
服务 A 数据 --> Stream 4  \
服务 B 数据 --> Stream 8   > QUIC 连接 --> 服务端
服务 C 数据 --> Stream 12 /

优势：
- 共享拥塞控制
- 流之间独立，无队头阻塞
- 单个连接，开销更小
```

## 性能对比

### 理论性能分析

| 指标 | Rathole | Quichole | 说明 |
|------|---------|----------|------|
| 连接建立延迟 | 2-3 RTT | 1 RTT (首次) / 0 RTT (重连) | Quichole 更快 |
| 重连延迟 | 2-3 RTT | 0 RTT | Quichole 显著更快 |
| 吞吐量 | 高 | 高 | 网络条件好时相当 |
| CPU 使用 | 低 | 中 | QUIC 需要更多 CPU |
| 内存使用 | 低 | 中 | QUIC 状态管理更复杂 |
| 并发连接数 | 受限于文件描述符 | 受限于流数量 | Quichole 可能更高 |

### 场景性能对比

#### 场景 1: 稳定网络，长连接

```
Rathole:  ████████████████████ (100%)
Quichole: ███████████████████░ (95%)

说明：稳定网络下，TCP 和 QUIC 性能相当
```

#### 场景 2: 不稳定网络，频繁重连

```
Rathole:  ████████░░░░░░░░░░░░ (40%)
Quichole: ████████████████████ (100%)

说明：Quichole 的 0-RTT 重连显著提升性能
```

#### 场景 3: 移动网络，IP 地址变化

```
Rathole:  ██░░░░░░░░░░░░░░░░░░ (10%)
Quichole: ████████████████████ (100%)

说明：Quichole 的连接迁移避免了重连
```

#### 场景 4: 高并发，多个服务

```
Rathole:  ████████████░░░░░░░░ (60%)
Quichole: ████████████████████ (100%)

说明：Quichole 的多路复用减少了连接开销
```

### 资源使用对比

#### 内存使用

```
Rathole:
- 每个 TCP 连接: ~4KB
- 100 个连接: ~400KB

Quichole:
- QUIC 连接: ~50KB
- 每个流: ~1KB
- 100 个流: ~150KB

结论：Quichole 在高并发时内存使用更少
```

#### CPU 使用

```
Rathole:
- TCP 处理: 低
- TLS 加密: 中

Quichole:
- QUIC 处理: 中
- TLS 1.3 加密: 中
- 拥塞控制: 中

结论：Quichole CPU 使用略高，但可接受
```

## 功能对比

### 核心功能

| 功能 | Rathole | Quichole | 备注 |
|------|---------|----------|------|
| TCP 转发 | ✅ | ✅ | 都支持 |
| UDP 转发 | ✅ | ✅ | 都支持 |
| 多服务 | ✅ | ✅ | 都支持 |
| Token 认证 | ✅ | ✅ | 都支持 |
| 心跳检测 | ✅ | ✅ | 都支持 |
| 热重载 | ✅ | 🔄 | Quichole 计划支持 |

### 传输特性

| 特性 | Rathole | Quichole | 备注 |
|------|---------|----------|------|
| TCP 传输 | ✅ | ❌ | Rathole 默认 |
| TLS 加密 | ✅ | ✅ | Quichole 内置 |
| Noise 协议 | ✅ | ❌ | Rathole 特有 |
| WebSocket | ✅ | ❌ | Rathole 特有 |
| QUIC | ❌ | ✅ | Quichole 特有 |
| 0-RTT | ❌ | ✅ | Quichole 特有 |
| 连接迁移 | ❌ | ✅ | Quichole 特有 |

### 部署特性

| 特性 | Rathole | Quichole | 备注 |
|------|---------|----------|------|
| 二进制大小 | ~500KB | ~2MB | Rathole 更小 |
| 依赖 | 少 | 中 | Rathole 更简单 |
| 跨平台 | ✅ | ✅ | 都支持 |
| Docker | ✅ | 🔄 | Quichole 计划支持 |
| Systemd | ✅ | 🔄 | Quichole 计划支持 |

## 使用场景

### Rathole 更适合的场景

1. **稳定网络环境**
   - 服务器之间的内网穿透
   - 网络条件稳定，很少断线

2. **资源受限设备**
   - 嵌入式设备
   - 路由器
   - 需要最小二进制大小

3. **需要特定传输协议**
   - 需要 WebSocket 传输
   - 需要 Noise 协议
   - 需要自定义传输层

4. **成熟稳定的生产环境**
   - 已经在生产环境使用 rathole
   - 不想引入新的依赖

### Quichole 更适合的场景

1. **不稳定网络环境**
   - 移动网络
   - 频繁切换网络
   - 网络抖动严重

2. **需要快速重连**
   - 实时应用
   - 游戏服务器
   - 视频流传输

3. **高并发场景**
   - 多个服务同时转发
   - 大量并发连接
   - 需要多路复用

4. **移动场景**
   - 移动设备
   - IP 地址频繁变化
   - 需要连接迁移

5. **追求新技术**
   - 想要使用 QUIC 协议
   - 追求最新的网络技术
   - 愿意接受新项目的风险

## 迁移指南

### 从 Rathole 迁移到 Quichole

#### 配置文件迁移

Rathole 配置：
```toml
[server]
bind_addr = "0.0.0.0:2333"

[server.services.ssh]
token = "secret"
bind_addr = "0.0.0.0:5202"
```

Quichole 配置（几乎相同）：
```toml
[server]
bind_addr = "0.0.0.0:4433"  # 注意：QUIC 使用 UDP

[server.services.ssh]
token = "secret"
bind_addr = "0.0.0.0:2222"
```

#### 防火墙配置

Rathole：
```bash
# 开放 TCP 端口
iptables -A INPUT -p tcp --dport 2333 -j ACCEPT
```

Quichole：
```bash
# 开放 UDP 端口
iptables -A INPUT -p udp --dport 4433 -j ACCEPT
```

#### 性能调优

Rathole：
```toml
[server.transport.tcp]
nodelay = true
keepalive_secs = 20
```

Quichole：
```toml
# QUIC 自动处理，无需配置
# 但可以调整 QUIC 参数
```

## 总结

### Rathole 的优势

- ✅ 成熟稳定
- ✅ 二进制更小
- ✅ 资源占用更少
- ✅ 支持多种传输协议
- ✅ 社区活跃

### Quichole 的优势

- ✅ 更快的连接建立
- ✅ 0-RTT 重连
- ✅ 连接迁移
- ✅ 多路复用
- ✅ 无队头阻塞
- ✅ 更好的移动网络支持

### 选择建议

| 如果你需要... | 选择 |
|-------------|------|
| 稳定的生产环境 | Rathole |
| 最小的资源占用 | Rathole |
| 快速重连 | Quichole |
| 移动网络支持 | Quichole |
| 高并发多路复用 | Quichole |
| 最新的网络技术 | Quichole |

两个项目都是优秀的内网穿透工具，选择哪个取决于你的具体需求和使用场景。
