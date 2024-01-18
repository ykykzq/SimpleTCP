/// 设置一些系统的常量

/// 本机的MAC地址 随便写的
pub const LOCAL_MAC:[u8;6]=[ 0x14, 0x5A, 0xFC, 0x15, 0x1A, 0x9D ];
/// 本机的IP地址
pub const LOCAL_IP:[u8;4]=[ 10, 10, 10, 3 ];
/// 网关的IP地址
pub const GATEWAY_IP:[u8;4]=[ 10, 10, 11, 1];
/// 子网掩码
pub const NETMASK:[u8;4]=[ 255, 255, 248, 0 ];
/// DNS服务器的IP地址
pub const DNS_SERVER_IP:[u8;4]=[ 211, 137, 130, 3 ];
/// DHCP服务器的IP地址
pub const DHCP_SERVER_IP:[u8;4]=[ 111, 20, 62, 57 ];
/// 广播MAC地址，全1
pub const BROADCAST_MAC:[u8;6] = [ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ];


