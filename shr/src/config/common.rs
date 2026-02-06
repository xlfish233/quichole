// 通用配置类型
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// 服务类型
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    #[default]
    Tcp,
    Udp,
}

/// TLS 配置（预留用于私有 CA / mTLS）
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// 证书路径（PEM）
    #[serde(default)]
    pub cert: Option<String>,
    /// 私钥路径（PEM）
    #[serde(default)]
    pub key: Option<String>,
    /// CA 证书路径（PEM）
    #[serde(default)]
    pub ca: Option<String>,
    /// 服务端名称（SNI）
    #[serde(default)]
    pub server_name: Option<String>,
    /// 是否校验服务端证书（客户端）
    #[serde(default)]
    pub verify_peer: bool,
    /// 是否要求客户端证书（服务端）
    #[serde(default)]
    pub require_client_cert: bool,
}

/// 客户端证书与私钥对
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertKeyPair {
    /// 客户端证书路径（PEM）
    pub cert: String,
    /// 客户端私钥路径（PEM）
    pub key: String,
}

/// 客户端 TLS 参数
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTlsParams {
    /// 客户端证书与私钥（mTLS 场景）
    pub cert_key: Option<ClientCertKeyPair>,
    /// CA 证书路径（用于验证服务端证书）
    pub ca: Option<String>,
}

impl TlsConfig {
    /// 验证服务端 TLS 配置
    ///
    /// # 错误
    /// - 如果 cert 或 key 未设置，返回错误
    /// - 如果要求客户端证书但未设置 CA，返回错误
    pub fn validate_server(&self) -> Result<()> {
        let cert = self.cert.as_deref().filter(|v| !v.is_empty());
        let key = self.key.as_deref().filter(|v| !v.is_empty());

        if cert.is_none() {
            bail!("tls.cert is required for server");
        }
        if key.is_none() {
            bail!("tls.key is required for server");
        }

        // 如果要求客户端证书，必须提供 CA
        if self.require_client_cert {
            let ca = self.ca.as_deref().filter(|v| !v.is_empty());
            if ca.is_none() {
                bail!("tls.ca is required when require_client_cert = true");
            }
        }

        Ok(())
    }

    /// 验证客户端 TLS 配置
    ///
    /// # 错误
    /// - 如果 cert 和 key 未成对出现，返回错误
    /// - 如果设置了 CA 但未设置 cert 和 key，返回错误
    pub fn validate_client(&self) -> Result<()> {
        let cert = self.cert.as_deref().filter(|v| !v.is_empty());
        let key = self.key.as_deref().filter(|v| !v.is_empty());
        let ca = self.ca.as_deref().filter(|v| !v.is_empty());

        // cert 和 key 必须成对出现
        if cert.is_some() ^ key.is_some() {
            bail!("tls.cert and tls.key must be set together");
        }

        // 如果设置了 CA（用于 mTLS），必须提供证书和密钥
        if ca.is_some() && cert.is_none() {
            bail!("tls.ca requires tls.cert and tls.key for client mTLS");
        }

        Ok(())
    }

    /// 提取服务端配置所需的参数
    ///
    /// # 返回值
    /// (cert, key, ca)
    pub fn server_params(&self) -> Result<(String, String, Option<String>)> {
        self.validate_server()?;

        let cert = self.cert.as_ref().unwrap().clone();
        let key = self.key.as_ref().unwrap().clone();
        let ca = self
            .ca
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        Ok((cert, key, ca))
    }

    /// 提取客户端配置所需的参数
    ///
    /// # 返回值
    /// (cert_key_pair, ca)
    pub fn client_params(&self) -> Result<ClientTlsParams> {
        self.validate_client()?;

        let cert_key = if let (Some(cert), Some(key)) = (&self.cert, &self.key) {
            if !cert.is_empty() && !key.is_empty() {
                Some(ClientCertKeyPair {
                    cert: cert.clone(),
                    key: key.clone(),
                })
            } else {
                None
            }
        } else {
            None
        };

        let ca = self
            .ca
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(str::to_string);

        Ok(ClientTlsParams { cert_key, ca })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_default() {
        assert_eq!(ServiceType::default(), ServiceType::Tcp);
    }

    #[test]
    fn test_service_type_serialization() {
        #[derive(Serialize)]
        struct Wrap {
            #[serde(rename = "type")]
            ty: ServiceType,
        }

        let tcp = Wrap {
            ty: ServiceType::Tcp,
        };
        let udp = Wrap {
            ty: ServiceType::Udp,
        };

        assert!(toml::to_string(&tcp).unwrap().contains("type = \"tcp\""));
        assert!(toml::to_string(&udp).unwrap().contains("type = \"udp\""));
    }

    #[test]
    fn test_service_type_deserialization() {
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(rename = "type")]
            ty: ServiceType,
        }

        let tcp: Wrap = toml::from_str("type = \"tcp\"").unwrap();
        let udp: Wrap = toml::from_str("type = \"udp\"").unwrap();

        assert_eq!(tcp.ty, ServiceType::Tcp);
        assert_eq!(udp.ty, ServiceType::Udp);
    }

    #[test]
    fn test_client_params_empty() {
        let tls = TlsConfig::default();
        let params = tls.client_params().unwrap();

        assert!(params.cert_key.is_none());
        assert!(params.ca.is_none());
    }

    #[test]
    fn test_client_params_with_cert_key() {
        let tls = TlsConfig {
            cert: Some("client.pem".to_string()),
            key: Some("client.key".to_string()),
            ..TlsConfig::default()
        };

        let params = tls.client_params().unwrap();
        assert_eq!(
            params.cert_key,
            Some(ClientCertKeyPair {
                cert: "client.pem".to_string(),
                key: "client.key".to_string(),
            })
        );
        assert!(params.ca.is_none());
    }

    #[test]
    fn test_client_params_requires_cert_key_when_ca_set() {
        let tls = TlsConfig {
            ca: Some("ca.pem".to_string()),
            ..TlsConfig::default()
        };

        let err = tls.client_params().unwrap_err();
        assert!(err.to_string().contains("tls.ca requires"));
    }

    #[test]
    fn test_client_params_empty_cert_key_treated_as_none() {
        let tls = TlsConfig {
            cert: Some(String::new()),
            key: Some(String::new()),
            ..TlsConfig::default()
        };

        let params = tls.client_params().unwrap();
        assert!(params.cert_key.is_none());
    }
}
