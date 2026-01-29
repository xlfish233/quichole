// 消息类型定义
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// 协议版本 1
pub const PROTO_V1: u8 = 1;

/// Hello 消息，用于初始化控制通道和数据通道
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Hello {
    /// 控制通道 Hello
    ///
    /// 客户端发送此消息以建立控制通道
    ControlChannelHello {
        /// 协议版本
        version: u8,
        /// 服务摘要 (SHA-256(service_name))
        service_digest: [u8; 32],
    },

    /// 数据通道 Hello
    ///
    /// 客户端发送此消息以建立数据通道
    DataChannelHello {
        /// 协议版本
        version: u8,
        /// 会话密钥（服务端生成）
        session_key: [u8; 32],
    },
}

impl Hello {
    /// 获取协议版本
    pub fn version(&self) -> u8 {
        match self {
            Hello::ControlChannelHello { version, .. } => *version,
            Hello::DataChannelHello { version, .. } => *version,
        }
    }

    /// 检查版本是否匹配
    pub fn is_version_compatible(&self) -> bool {
        self.version() == PROTO_V1
    }
}

/// Auth 消息，用于客户端认证
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Auth {
    /// 认证摘要 (SHA-256(token + nonce))
    pub digest: [u8; 32],
}

/// Ack 消息，服务端对客户端请求的响应
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Ack {
    /// 认证成功
    Ok,
    /// 服务不存在
    ServiceNotExist,
    /// 认证失败
    AuthFailed,
}

/// 控制通道命令，服务端通过控制通道发送的命令
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ControlChannelCmd {
    /// 请求客户端创建新的数据通道
    CreateDataChannel,
    /// 心跳消息
    Heartbeat,
}

/// 数据通道命令，服务端通过数据通道发送的命令
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DataChannelCmd {
    /// 开始 TCP 转发
    StartForwardTcp,
    /// 开始 UDP 转发
    StartForwardUdp,
}

/// UDP 流量封装，UDP 数据包需要携带源地址信息
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpTraffic {
    /// 源地址
    pub from: SocketAddr,
    /// UDP 数据
    pub data: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_control_channel_serialization() {
        let hello = Hello::ControlChannelHello {
            version: 1,
            service_digest: [0u8; 32],
        };

        let encoded = bincode::serialize(&hello).unwrap();
        let decoded: Hello = bincode::deserialize(&encoded).unwrap();

        assert_eq!(hello, decoded);
    }

    #[test]
    fn test_hello_data_channel_serialization() {
        let hello = Hello::DataChannelHello {
            version: 1,
            session_key: [1u8; 32],
        };

        let encoded = bincode::serialize(&hello).unwrap();
        let decoded: Hello = bincode::deserialize(&encoded).unwrap();

        assert_eq!(hello, decoded);
    }

    #[test]
    fn test_auth_serialization() {
        let auth = Auth { digest: [2u8; 32] };

        let encoded = bincode::serialize(&auth).unwrap();
        let decoded: Auth = bincode::deserialize(&encoded).unwrap();

        assert_eq!(auth, decoded);
    }

    #[test]
    fn test_ack_serialization() {
        let acks = vec![Ack::Ok, Ack::ServiceNotExist, Ack::AuthFailed];

        for ack in acks {
            let encoded = bincode::serialize(&ack).unwrap();
            let decoded: Ack = bincode::deserialize(&encoded).unwrap();
            assert_eq!(ack, decoded);
        }
    }

    #[test]
    fn test_control_channel_cmd_serialization() {
        let cmds = vec![
            ControlChannelCmd::CreateDataChannel,
            ControlChannelCmd::Heartbeat,
        ];

        for cmd in cmds {
            let encoded = bincode::serialize(&cmd).unwrap();
            let decoded: ControlChannelCmd = bincode::deserialize(&encoded).unwrap();
            assert_eq!(cmd, decoded);
        }
    }

    #[test]
    fn test_data_channel_cmd_serialization() {
        let cmds = vec![
            DataChannelCmd::StartForwardTcp,
            DataChannelCmd::StartForwardUdp,
        ];

        for cmd in cmds {
            let encoded = bincode::serialize(&cmd).unwrap();
            let decoded: DataChannelCmd = bincode::deserialize(&encoded).unwrap();
            assert_eq!(cmd, decoded);
        }
    }

    #[test]
    fn test_udp_traffic_serialization() {
        use bytes::Bytes;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let traffic = UdpTraffic {
            from: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            data: Bytes::from("test data"),
        };

        let encoded = bincode::serialize(&traffic).unwrap();
        let decoded: UdpTraffic = bincode::deserialize(&encoded).unwrap();

        assert_eq!(traffic.from, decoded.from);
        assert_eq!(traffic.data, decoded.data);
    }

    #[test]
    fn test_hello_version() {
        let hello1 = Hello::ControlChannelHello {
            version: PROTO_V1,
            service_digest: [0u8; 32],
        };
        assert_eq!(hello1.version(), PROTO_V1);

        let hello2 = Hello::DataChannelHello {
            version: PROTO_V1,
            session_key: [0u8; 32],
        };
        assert_eq!(hello2.version(), PROTO_V1);
    }

    #[test]
    fn test_hello_version_compatibility() {
        let hello_compatible = Hello::ControlChannelHello {
            version: PROTO_V1,
            service_digest: [0u8; 32],
        };
        assert!(hello_compatible.is_version_compatible());

        let hello_incompatible = Hello::ControlChannelHello {
            version: 99,
            service_digest: [0u8; 32],
        };
        assert!(!hello_incompatible.is_version_compatible());
    }
}
