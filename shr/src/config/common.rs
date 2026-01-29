// 通用配置类型
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
}
