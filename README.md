# Quichole

基于 QUIC 的安全、高性能内网穿透工具，面向多路复用与低延迟场景。

适合：需要更低队头阻塞、连接迁移与 0-RTT 重连的内网服务暴露。

![CI](https://img.shields.io/github/actions/workflow/status/xlfish233/quichole/ci.yml?branch=master)
![License](https://img.shields.io/github/license/xlfish233/quichole)
![Release](https://img.shields.io/github/v/release/xlfish233/quichole)

**快速链接**：[部署指南](docs/DEPLOYMENT.md) | [安全文档](docs/SECURITY.md) | [运维手册](docs/OPERATIONS.md) | [配置说明](docs/CONFIGURATION.md)

## 特性

- 🚀 **高性能**: 基于 QUIC 协议，支持多路复用，无队头阻塞
- 🔒 **安全**: 内置 TLS 1.3 加密，支持服务级别的 token 认证
- ⚡ **快速重连**: 支持 0-RTT 连接恢复
- 📱 **连接迁移**: IP 地址变化时连接不中断
- 🪶 **轻量级**: 最小化资源占用，适合嵌入式设备
- 🔧 **易配置**: 简单的 TOML 配置文件

## 为什么是 QUIC

- 多路复用避免队头阻塞
- 连接迁移适应 IP 变化
- 0-RTT 让重连更快

## 安装

### 从 Release 下载

前往 [Releases](https://github.com/xlfish233/quichole/releases) 下载对应平台的预编译二进制。

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/xlfish233/quichole.git
cd quichole

# 编译 release 版本
cargo build --release

# 二进制位于
# ./target/release/quichole-svr  (服务端)
# ./target/release/quichole-cli  (客户端)
```

## 快速开始（最小可运行）

1) 准备配置文件

`server.toml`：

```toml
bind_addr = "0.0.0.0:4433"
default_token = "demo_secret"

[tls]
cert = "certs/server.pem"
key = "certs/server.key"

[services.ssh]
bind_addr = "0.0.0.0:2222"
token = ""
type = "tcp"
```

`client.toml`：

```toml
remote_addr = "your-server.com:4433"
default_token = "demo_secret"

[tls]
server_name = "your-server.com"

[services.ssh]
local_addr = "127.0.0.1:22"
token = ""
type = "tcp"
```

2) 生成证书（开发环境，SAN 要匹配 `server_name`）

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/server.key \
  -out certs/server.pem \
  -days 365 \
  -subj "/CN=your-server.com" \
  -addext "subjectAltName=DNS:your-server.com"
```

3) 运行

```bash
quichole-svr -c server.toml
quichole-cli -c client.toml
```

现在你可以通过 `your-server.com:2222` 访问内网 SSH。

> 生产部署与运维请看：`docs/DEPLOYMENT.md`

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

## 文档导航

| 主题 | 入口 |
|------|------|
| 架构与时序图 | `ARCHITECTURE.md` |
| 协议说明 | `docs/PROTOCOL.md` |
| 配置说明 | `docs/CONFIGURATION.md` |
| 实施/阶段说明 | `docs/IMPLEMENTATION.md` |
| 生产部署与运维 | `docs/DEPLOYMENT.md` |
| 安全与证书 | `docs/SECURITY.md` |
| 运维与排障 | `docs/OPERATIONS.md` |

## 适合 / 不适合

| 适合 | 不适合 |
|------|--------|
| 需要多路复用、避免队头阻塞的内网穿透 | UDP 被严格屏蔽的网络环境 |
| 频繁切换网络（移动网络）或需要连接迁移 | 只能接受 TCP 转发的封闭网络 |
| 对握手延迟敏感，期望 0-RTT 重连 | |

## 生产就绪声明

- 当前为早期开发阶段，已具备 MVP 与端到端测试
- 建议生产使用前进行小规模灰度与压测
- 生产部署与运维细节见 `docs/DEPLOYMENT.md`

## 与 rathole 的对比

| 特性 | quichole | rathole |
|------|----------|---------|
| 传输协议 | QUIC (UDP) | TCP/TLS/Noise/WebSocket |
| 多路复用 | ✅ 原生支持 | ❌ 需要多个连接 |
| 0-RTT | ✅ 支持 | ❌ |
| 连接迁移 | ✅ 支持 | ❌ |
| NAT 穿透 | ✅ 更容易 (UDP) | ⚠️ 较难 (TCP) |
| 队头阻塞 | ✅ 无 | ⚠️ 可能存在 |

## FAQ

- **连接失败**：检查 UDP 入站、防火墙与安全组，详见 [运维文档](docs/OPERATIONS.md#连接问题)
- **证书校验失败**：确认 `server_name` 与证书 SAN 匹配，详见 [安全文档](docs/SECURITY.md)
- **服务不可达**：检查 `bind_addr`/`local_addr` 是否正确，详见 [配置文档](docs/CONFIGURATION.md)
- **频繁重连**：调节心跳参数，检查网络抖动，详见 [运维文档](docs/OPERATIONS.md#重连问题)
- **mTLS 失败**：确认 `tls.ca`、`tls.cert`、`tls.key` 是否齐全，详见 [安全文档](docs/SECURITY.md#mtls)

## 路线图（简版）

- 集成测试覆盖更多异常场景
- 运维/观测能力增强（日志/指标）
- 性能基准与压测报告

## 贡献

欢迎提交 issue 或 PR。建议附带复现步骤、日志与配置片段。

## 许可证

MIT OR Apache-2.0

## 系统要求

- **Rust**: 1.70+ (edition 2021)
- **操作系统**: Linux, macOS, Windows
- **网络**: 需要 UDP 出站（客户端）/ 入站（服务端）
