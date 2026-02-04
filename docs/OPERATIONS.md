# 运维与故障排查（日志为主）

本指南关注运行期可观测性与常见故障排查路径。

## 日志建议

- 默认使用 `info` 级别
- 排障时可临时提升为 `debug` 或 `trace`
- 生产建议使用结构化日志并保留关键字段

### 常用环境变量

```bash
# 临时提高日志级别
RUST_LOG=info
RUST_LOG=quichole_svr=debug,quichole_cli=debug
```

## 关键日志字段（示例）

- `bind_addr`：服务端监听地址
- `remote_addr`：客户端连接目标
- `service`/`service_name`：服务标识
- `stream_id`：数据通道流编号
- `error`：错误原因

## 故障排查清单

### 1) 无法建立连接

- 检查 UDP 入站是否被防火墙/安全组拦截
- 确认服务端 `bind_addr` 与客户端 `remote_addr` 配置正确
- 检查 `server_name` 与证书是否匹配

### 2) 认证失败

- 服务端与客户端 token 是否一致
- mTLS 是否正确配置：`tls.ca`、`tls.cert`、`tls.key`
- 证书是否过期、权限是否可读

### 3) 服务不可达

- 服务端 `services.*.bind_addr` 是否已被占用
- 客户端 `services.*.local_addr` 是否真实可用
- 服务类型 `tcp/udp` 是否与目标一致

### 4) 频繁重连

- 调整 `heartbeat_interval` 与 `heartbeat_timeout`
- 检查网络抖动、丢包、NAT 设备是否重映射

### 5) 数据通道无流量

- 检查控制通道是否建立成功
- 使用 `debug` 级别确认数据通道是否创建
- 确认本地服务是否有真实流量

## 健康检查建议

- 使用端口可达性检查（服务端暴露端口）
- 结合日志关键字段判断连接是否稳定
- 在 e2e 测试成功的基础上复用相同配置排障

## 运行期维护建议

- 控制日志体积与保留周期
- 定期轮换证书与 token
- 升级前保留可回滚的二进制
