// message/version_payload.rs

use crate::message::bytes::Bytes;
use crate::message::net_addr::NetAddr;
use crate::message::var_str::VarStr;
use crate::message::endianness::*;

/// Payload for the "version" message.
#[derive(Debug, Clone)]
pub struct VersionPayload {
    pub version: i32,
    pub services: u64,
    pub timestamp: i64,
    pub addr_recv: NetAddr,
    pub addr_from: NetAddr,
    pub nonce: u64,
    pub user_agent: VarStr,
    pub start_height: i32,
    pub relay: bool,
}

impl VersionPayload {
    pub fn new(
        addr_recv: NetAddr,
        addr_from: NetAddr,
        user_agent: VarStr,
    ) -> Self {
        VersionPayload {
            version: 70018,
            services: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            addr_recv,
            addr_from,
            nonce: rand::random(),
            user_agent,
            start_height: 0,
            relay: false,
        }
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.services.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.addr_recv.serialize(false));
        buf.extend_from_slice(&self.addr_from.serialize(false));
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.user_agent.serialize());
        buf.extend_from_slice(&self.start_height.to_le_bytes());
        buf.push(self.relay as u8);
        buf
    }

    /// Parse a version payload from `bytes`, returning the parsed value and bytes consumed.
    pub fn parse(bytes: &[u8]) -> (VersionPayload, usize) {
        let mut offset = 0;

        let version = read_i32_le(&bytes[offset..offset + 4]);
        offset += 4;
        let services = read_u64_le(&bytes[offset..offset + 8]);
        offset += 8;
        let timestamp = read_i64_le(&bytes[offset..offset + 8]);
        offset += 8;

        let (addr_recv, consumed) = NetAddr::parse(&bytes[offset..], false);
        offset += consumed;

        let (addr_from, consumed) = NetAddr::parse(&bytes[offset..], false);
        offset += consumed;

        let nonce = read_u64_le(&bytes[offset..offset + 8]);
        offset += 8;

        let (user_agent, consumed) = VarStr::parse(&bytes[offset..]);
        offset += consumed;

        let start_height = read_i32_le(&bytes[offset..offset + 4]);
        offset += 4;
        let relay = bytes[offset] != 0;
        offset += 1;

        (
            VersionPayload {
                version,
                services,
                timestamp,
                addr_recv,
                addr_from,
                nonce,
                user_agent,
                start_height,
                relay,
            },
            offset,
        )
    }
}
