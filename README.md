# Quichole

一个基于 QUIC 协议的安全、高性能内网穿透工具。

## 特性

- 🚀 **高性能**: 基于 QUIC 协议，支持多路复用，无队头阻塞
- 🔒 **安全**: 内置 TLS 1.3 加密，支持服务级别的 token 认证
- ⚡ **快速重连**: 支持 0-RTT 连接恢复
- 📱 **连接迁移**: IP 地址变化时连接不中断
- 🪶 **轻量级**: 最小化资源占用，适合嵌入式设备
- 🔧 **易配置**: 简单的 TOML 配置文件

## 架构

```
客户端 (内网)          服务端 (公网)           访问者
    |                      |                    |
    |-- QUIC 控制通道 ----->|                    |
    |   (认证/心跳)         |                    |
    |                      |<--- TCP 连接 ------|
    |<-- QUIC 数据流 -------|                    |
    |   (转发流量)          |                    |
    |                      |                    |
    +--> 本地服务          |                    |
```

## 快速开始

### 构建依赖

在编译 quichole 之前，需要安装以下依赖：

**Linux (Arch/Manjaro):**
```bash
sudo pacman -S cmake
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install cmake build-essential
```

**macOS:**
```bash
brew install cmake
```

**Windows:**
- 安装 [CMake](https://cmake.org/download/)
- 安装 [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)

> **注意**: quiche 依赖 BoringSSL，需要 cmake 来编译。

### 从源码安装

```bash
git clone https://github.com/yourusername/quichole.git
cd quichole
cargo build --release
```

安装到系统：
```bash
cargo install --path ./svr  # 安装服务端
cargo install --path ./cli  # 安装客户端
```

### 服务端配置

创建 `server.toml`:

```toml
bind_addr = "0.0.0.0:4433"

[tls]
cert = "certs/server.pem"
key = "certs/server.key"
# ca = "certs/ca.pem"
# require_client_cert = true

[services.my_ssh]
token = "your_secret_token"
bind_addr = "0.0.0.0:2222"
```

生成自签证书（开发环境）：

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/server.key \
  -out certs/server.pem \
  -days 365 \
  -subj "/CN=localhost"
```

运行服务端:

```bash
quichole-server -c server.toml
```

### 客户端配置

创建 `client.toml`:

```toml
remote_addr = "your-server.com:4433"

[tls]
server_name = "your-server.com"
# ca = "certs/ca.pem"
# verify_peer = true
# cert = "certs/client.pem"
# key = "certs/client.key"

[services.my_ssh]
token = "your_secret_token"
local_addr = "127.0.0.1:22"
```

运行客户端:

```bash
quichole-client -c client.toml
```

现在你可以通过 `your-server.com:2222` 访问内网的 SSH 服务了！

> 若需私有 CA / mTLS：服务端配置 `tls.ca` + `require_client_cert = true`，客户端配置 `tls.ca` + `tls.cert` + `tls.key` 并设置 `tls.verify_peer = true`。

## 与 rathole 的对比

| 特性 | quichole | rathole |
|------|----------|---------|
| 传输协议 | QUIC (UDP) | TCP/TLS/Noise/WebSocket |
| 多路复用 | ✅ 原生支持 | ❌ 需要多个连接 |
| 0-RTT | ✅ 支持 | ❌ |
| 连接迁移 | ✅ 支持 | ❌ |
| NAT 穿透 | ✅ 更容易 (UDP) | ⚠️ 较难 (TCP) |
| 队头阻塞 | ✅ 无 | ⚠️ 可能存在 |

## 开发状态

🚧 **项目处于早期开发阶段**

- [x] 项目架构设计
- [x] 协议定义（Phase 1）
- [x] 加密/认证模块（Phase 3）
- [x] 配置文件支持（Phase 2.1/2.2）
- [x] 服务端实现（MVP 传输/转发）
- [x] 客户端实现（MVP 传输/转发）
- [x] 端到端测试（QUIC TCP + mTLS）
- [ ] 更丰富的集成测试
- [ ] 文档完善（持续更新）

## 许可证

MIT OR Apache-2.0
