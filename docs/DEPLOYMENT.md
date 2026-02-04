# 生产部署与运维（systemd）

本文档面向传统 Linux 服务器的生产部署，使用 systemd 管理服务。

## 前置条件

- 公网服务器允许 UDP 入站（QUIC 运行在 UDP 上）
- 已准备服务端与客户端二进制
- 已准备证书（TLS 或 mTLS）
- 具备 root 或等效权限用于安装与 systemd 配置

## 推荐目录布局

```
/etc/quichole/
  bin/
  server.toml
  client.toml
  certs/
/var/lib/quichole/
/var/log/quichole/
```

建议创建独立用户运行服务：

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin quichole
sudo mkdir -p /etc/quichole/bin /etc/quichole/certs /var/lib/quichole /var/log/quichole
sudo chown -R quichole:quichole /etc/quichole /var/lib/quichole /var/log/quichole
sudo chmod 700 /etc/quichole/certs
```

## 安装二进制（下载到 /etc）

将发布的二进制放到 `/etc/quichole/bin`，并确保可执行权限：

```bash
sudo mv quichole-server /etc/quichole/bin/quichole-server
sudo mv quichole-client /etc/quichole/bin/quichole-client
sudo chown quichole:quichole /etc/quichole/bin/quichole-*
sudo chmod 755 /etc/quichole/bin/quichole-*
```

## systemd 配置（服务端）

创建 `/etc/systemd/system/quichole-server.service`：

```ini
[Unit]
Description=Quichole Server
After=network-online.target
Wants=network-online.target

[Service]
User=quichole
Group=quichole
WorkingDirectory=/var/lib/quichole
ExecStart=/etc/quichole/bin/quichole-server -c /etc/quichole/server.toml
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

# 日志写入 journald（默认）
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quichole-server
```

查看状态与日志：

```bash
sudo systemctl status quichole-server
sudo journalctl -u quichole-server -f
```

## systemd 配置（客户端）

创建 `/etc/systemd/system/quichole-client.service`：

```ini
[Unit]
Description=Quichole Client
After=network-online.target
Wants=network-online.target

[Service]
User=quichole
Group=quichole
WorkingDirectory=/var/lib/quichole
ExecStart=/etc/quichole/bin/quichole-client -c /etc/quichole/client.toml
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quichole-client
```

## 证书与权限

- 服务端必须提供 `tls.cert` 与 `tls.key`
- 启用 mTLS 时服务端还需要 `tls.ca`
- 客户端启用私有 CA 或 mTLS 时需要 `tls.ca` + `tls.cert` + `tls.key`
- 证书与私钥文件建议权限为 `600`，所有者为 `quichole`
 - 默认日志输出到 journald，若需写入 `/var/log/quichole`，请在配置中启用文件日志

示例：

```bash
sudo chown quichole:quichole /etc/quichole/certs/*
sudo chmod 600 /etc/quichole/certs/*.key
sudo chmod 600 /etc/quichole/certs/*.pem
```

## 升级与回滚

1. 备份当前二进制与配置
2. 替换二进制（保持路径不变）
3. `systemctl restart` 触发平滑重启
4. 若失败，回滚旧二进制并重启

示例：

```bash
sudo cp /usr/local/bin/quichole-server /usr/local/bin/quichole-server.bak
sudo systemctl restart quichole-server
```

## 常见问题

- 无法连接：检查 UDP 入站与安全组、防火墙规则
- 证书错误：检查 `server_name`、证书路径与权限
- 频繁重连：检查心跳超时与网络抖动
