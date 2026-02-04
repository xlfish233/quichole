# 安全与证书（实用指南）

本指南聚焦可落地的安全基线与 mTLS 证书实践。

## 安全基线（建议）

- 使用最小权限用户运行服务
- token 不要写入日志或公开仓库
- 证书与私钥文件限制权限（`600`）
- 服务端与客户端分离配置与证书目录

## mTLS 启用步骤

### 服务端配置示例

```toml
[tls]
cert = "/etc/quichole/certs/server.pem"
key = "/etc/quichole/certs/server.key"
ca = "/etc/quichole/certs/ca.pem"
require_client_cert = true
```

### 客户端配置示例

```toml
[tls]
server_name = "your-server.com"
ca = "/etc/quichole/certs/ca.pem"
verify_peer = true
cert = "/etc/quichole/certs/client.pem"
key = "/etc/quichole/certs/client.key"
```

## 证书生成（自签 CA 示例）

以下示例使用 OpenSSL 生成一套可用于 mTLS 的 CA、服务端证书与客户端证书。

```bash
# 生成 CA
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout ca.key -out ca.pem -subj "/CN=quichole-ca"

# 生成服务端证书（SAN 必须包含 server_name）
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=your-server.com" \
  -addext "subjectAltName=DNS:your-server.com,IP:1.2.3.4"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 365

# 生成客户端证书
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=quichole-client"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -days 365
```

## 证书轮换建议

- 先在服务端部署新证书并重启
- 客户端更新 CA 与自身证书后重启
- 轮换完成后再移除旧证书

## 常见坑

- `server_name` 与证书 SAN 不匹配导致握手失败
- 证书路径错误或权限不足导致无法读取
- 客户端启用 `tls.ca` 时必须配置 `tls.cert` + `tls.key`
- 服务器时间偏差过大导致证书被视为过期

## Token 管理建议

- 不要在共享环境使用同一个 token
- 定期轮换 token，并同步客户端配置
- 排障时避免将 token 直接输出到日志
