// message/net_addr.rs

use crate::message::bytes::Bytes;
use crate::message::endianness::*;

/// Network address: time + services + 16-byte IPv6-mapped address + port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAddr {
    pub time: u32,
    pub services: u64,
    pub ip: [u8; 16],
    pub port: u16,
}

impl NetAddr {
    pub fn new(time: u32, services: u64, ip: [u8; 16], port: u16) -> Self {
        NetAddr {
            time,
            services,
            ip,
            port,
        }
    }

    pub fn serialize(&self, include_time: bool) -> Bytes {
        let mut buf = Vec::new();
        if include_time {
            buf.extend_from_slice(&self.time.to_le_bytes());
        }
        buf.extend_from_slice(&self.services.to_le_bytes());
        buf.extend_from_slice(&self.ip);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }

    /// Parse a net_addr from `bytes`, returning the parsed value and bytes consumed.
    pub fn parse(bytes: &[u8], include_time: bool) -> (NetAddr, usize) {
        let mut offset = 0;
        let time = if include_time {
            let t = read_u32_le(&bytes[offset..offset + 4]);
            offset += 4;
            t
        } else {
            0
        };
        let services = read_u64_le(&bytes[offset..offset + 8]);
        offset += 8;
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&bytes[offset..offset + 16]);
        offset += 16;
        let port = read_u16_be(&bytes[offset..offset + 2]);
        offset += 2;
        (
            NetAddr {
                time,
                services,
                ip,
                port,
            },
            offset,
        )
    }
}
