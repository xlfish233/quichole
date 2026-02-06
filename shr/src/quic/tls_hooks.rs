/// 统一的 TLS Hooks 构建器
///
/// 提供服务端和客户端共用的 TLS 配置和证书验证逻辑
use anyhow::Result;
use boring::ssl::{SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};
use boring::x509::X509;
use std::sync::Arc;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::settings::{CertificateKind, Hooks, TlsCertificatePaths};

/// TLS 连接角色
#[derive(Debug, Clone, Copy)]
pub enum TlsRole {
    /// 服务端角色
    Server {
        /// 是否要求客户端提供证书
        require_client_cert: bool,
    },
    /// 客户端角色
    Client {
        /// 是否验证服务端证书
        verify_peer: bool,
    },
}

/// 统一的 TLS Hook 实现
struct UnifiedTlsHook {
    ca: Option<String>,
    role: TlsRole,
}

impl ConnectionHook for UnifiedTlsHook {
    fn create_custom_ssl_context_builder(
        &self,
        settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        if settings.kind != CertificateKind::X509 {
            return None;
        }

        let mut builder = SslContextBuilder::new(SslMethod::tls()).ok()?;

        // 加载证书链
        if let Err(err) = builder.set_certificate_chain_file(settings.cert) {
            let role = match self.role {
                TlsRole::Server { .. } => "server",
                TlsRole::Client { .. } => "client",
            };
            tracing::warn!(error = %err, role, "failed to load certificate");
            return None;
        }

        // 加载私钥
        if let Err(err) = builder.set_private_key_file(settings.private_key, SslFiletype::PEM) {
            let role = match self.role {
                TlsRole::Server { .. } => "server",
                TlsRole::Client { .. } => "client",
            };
            tracing::warn!(error = %err, role, "failed to load private key");
            return None;
        }

        // 验证私钥匹配
        if let Err(err) = builder.check_private_key() {
            let role = match self.role {
                TlsRole::Server { .. } => "server",
                TlsRole::Client { .. } => "client",
            };
            tracing::warn!(error = %err, role, "private key mismatch");
            return None;
        }

        // 加载 CA 文件
        if let Some(ca) = &self.ca {
            if let Err(err) = builder.set_ca_file(ca) {
                let role = match self.role {
                    TlsRole::Server { .. } => "server",
                    TlsRole::Client { .. } => "client",
                };
                tracing::warn!(error = %err, role, "failed to load CA file");
                return None;
            }

            // 服务端需要添加客户端 CA 列表（用于 mTLS）
            if matches!(self.role, TlsRole::Server { .. }) {
                if let Ok(pem) = std::fs::read(ca) {
                    if let Ok(certs) = X509::stack_from_pem(&pem) {
                        for cert in certs {
                            let _ = builder.add_client_ca(&cert);
                        }
                    }
                }
            }
        }

        // 配置验证模式
        match self.role {
            TlsRole::Server {
                require_client_cert,
            } => {
                if require_client_cert {
                    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
                }
            }
            TlsRole::Client { verify_peer } => {
                if verify_peer {
                    builder.set_verify(SslVerifyMode::PEER);
                }
            }
        }

        Some(builder)
    }
}

/// 为服务端构建 TLS Hooks
///
/// # 参数
/// - `ca`: CA 证书文件路径（用于验证客户端证书）
/// - `require_client_cert`: 是否要求客户端提供证书
///
/// # 返回值
/// - 如果 `ca` 为 None 且不要求客户端证书，返回默认 Hooks
/// - 否则返回配置了自定义 TLS 验证的 Hooks
pub fn build_server_tls_hooks(ca: Option<String>, require_client_cert: bool) -> Result<Hooks> {
    if ca.is_none() && !require_client_cert {
        return Ok(Hooks::default());
    }

    let hook = UnifiedTlsHook {
        ca,
        role: TlsRole::Server {
            require_client_cert,
        },
    };

    Ok(Hooks {
        connection_hook: Some(Arc::new(hook)),
    })
}

/// 为客户端构建 TLS Hooks
///
/// # 参数
/// - `ca`: CA 证书文件路径（用于验证服务端证书，或用于 mTLS）
/// - `verify_peer`: 是否验证服务端证书
///
/// # 返回值
/// - 如果 `ca` 为 None，返回默认 Hooks
/// - 否则返回配置了自定义 TLS 验证的 Hooks
pub fn build_client_tls_hooks(ca: Option<String>, verify_peer: bool) -> Result<Hooks> {
    if ca.is_none() {
        return Ok(Hooks::default());
    }

    let hook = UnifiedTlsHook {
        ca,
        role: TlsRole::Client { verify_peer },
    };

    Ok(Hooks {
        connection_hook: Some(Arc::new(hook)),
    })
}
