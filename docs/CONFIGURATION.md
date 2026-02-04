# Quichole 配置说明

本文档描述 quichole 的配置文件格式、默认值与校验规则。

> 当前实现使用**顶层字段**格式，不包含 `[server]` / `[client]` 外层表。

## 文档导航

- 架构与时序图：`ARCHITECTURE.md`
- 协议说明：`docs/PROTOCOL.md`
- 实施/阶段说明：`docs/IMPLEMENTATION.md`
- 生产部署与运维：`docs/DEPLOYMENT.md`
- 安全与证书：`docs/SECURITY.md`
- 运维与排障：`docs/OPERATIONS.md`

## 服务端配置（server.toml）

```toml
bind_addr = "0.0.0.0:4433"
heartbeat_interval = 30
# 可选：心跳 ACK 超时，默认 heartbeat_interval * 3
# heartbeat_ack_timeout = 90
# 可选：QUIC 空闲超时（毫秒）
# quic_idle_timeout_ms = 60000
# 可选：为未填写 token 的服务提供默认值
# default_token = "default_secret"

[tls]
cert = "certs/server.pem"
key = "certs/server.key"
# ca = "certs/ca.pem"          # 启用 mTLS 时填写
# require_client_cert = false  # 启用 mTLS 时设为 true

[services.ssh]
bind_addr = "0.0.0.0:2222"
token = "ssh_secret"
type = "tcp"

[services.dns]
bind_addr = "0.0.0.0:5353"
# token 为空时会使用 default_token
type = "udp"
```

字段说明：

- `bind_addr`：服务端 QUIC 监听地址
- `heartbeat_interval`：心跳间隔（秒，默认 30）
- `heartbeat_ack_timeout`：心跳 ACK 超时（秒，默认 `heartbeat_interval * 3`）
- `quic_idle_timeout_ms`：QUIC 空闲超时（毫秒，可选）
- `default_token`：服务级 token 的默认值（可选）
- `tls`：TLS 配置（支持私有 CA / mTLS）
  - `cert`：服务端证书路径（PEM）
  - `key`：服务端私钥路径（PEM）
  - `ca`：CA 证书路径（用于校验客户端证书；`require_client_cert = true` 时必填）
  - `require_client_cert`：是否要求客户端证书（mTLS）
- `services`：服务列表（至少一个）
  - `bind_addr`：服务暴露地址
  - `token`：服务 token（可为空，若 `default_token` 已配置会自动填充）
  - `type`：服务类型，`tcp` 或 `udp`（默认 `tcp`）

## 客户端配置（client.toml）

```toml
remote_addr = "example.com:4433"
heartbeat_timeout = 40
retry_interval = 1
# 可选：QUIC 空闲超时（毫秒）
# quic_idle_timeout_ms = 60000
# 可选：为未填写 token 的服务提供默认值
# default_token = "default_secret"

[tls]
server_name = "example.com"
# ca = "certs/ca.pem"       # 私有 CA / mTLS
# verify_peer = true        # 启用服务端证书校验
# cert = "certs/client.pem" # mTLS 客户端证书
# key = "certs/client.key"  # mTLS 客户端私钥

[services.ssh]
local_addr = "127.0.0.1:22"
token = "ssh_secret"
type = "tcp"

[services.dns]
local_addr = "127.0.0.1:53"
# token 为空时会使用 default_token
type = "udp"
# 覆盖全局 retry_interval
retry_interval = 5
```

字段说明：

- `remote_addr`：服务端地址
- `heartbeat_timeout`：心跳超时（秒，默认 40）
- `retry_interval`：重试间隔（秒，默认 1）
- `quic_idle_timeout_ms`：QUIC 空闲超时（毫秒，可选）
- `default_token`：服务级 token 的默认值（可选）
- `tls`：TLS 配置（支持私有 CA / mTLS）
  - `server_name`：SNI 名称（可选，默认从 `remote_addr` 提取）
  - `ca`：CA 证书路径（私有 CA；配置后需同时提供 `cert`/`key`）
  - `verify_peer`：是否校验服务端证书（true 时启用；未配置 `ca` 则使用系统 CA）
  - `cert` / `key`：客户端证书与私钥（mTLS）
- `services`：服务列表（至少一个）
  - `local_addr`：本地服务地址
  - `token`：服务 token（可为空，若 `default_token` 已配置会自动填充）
  - `type`：服务类型，`tcp` 或 `udp`（默认 `tcp`）
  - `retry_interval`：覆盖全局重试间隔（可选）

## 校验规则（Phase 2.2）

- 必填字段非空：
  - 服务端：`bind_addr`
  - 客户端：`remote_addr`
  - 每个服务：`bind_addr` / `local_addr`
- 数值必须大于 0：
  - `heartbeat_interval` / `heartbeat_ack_timeout` / `heartbeat_timeout`
  - `retry_interval`（全局与服务级）
- `services` 必须至少包含一个服务
- 服务 token 为空时会尝试用 `default_token` 填充；若仍为空则报错
- TLS 证书为运行时依赖：服务端需要提供 `tls.cert` + `tls.key`
- 当 `tls.require_client_cert = true` 时，服务端还需要 `tls.ca`
- 客户端启用私有 CA / mTLS（配置 `tls.ca`）时，需要提供 `tls.cert` + `tls.key`

## 日志配置（server/client 通用）

日志配置在服务端/客户端均通过 `logging` 字段提供。示例：

```toml
[logging]
level = "info"
format = "pretty"           # pretty/json
with_file_location = false
with_target = true

[logging.console]
enabled = true
use_stderr = false
ansi = true

[logging.file]
enabled = false
directory = "/var/log/quichole"
prefix = "quichole"
rotation_size = 104857600    # 100 MB
rotation_interval = "daily"  # hourly/daily/never
retention_count = 30
separate_error_log = false
level = "debug"

[logging.filters]
overrides = "quichole_svr=debug,quichole_cli=debug"

[logging.redaction]
enabled = true

[logging.metrics]
enabled = false
interval_seconds = 60
include_connection_stats = true
include_memory_stats = false

[logging.async]
buffer_size = 1024
backpressure_behavior = "block" # block/drop
```

## CLI 使用

- 服务端：`quichole-server -c server.toml`
- 客户端：`quichole-client -c client.toml`
