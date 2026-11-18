// message/addr_payload.rs

use crate::message::net_addr::NetAddr;
use crate::message::var_int::VarInt;

/// Payload for the "addr" message: a varint count followed by that many NetAddr entries.
#[derive(Debug, Clone)]
pub struct AddrPayload {
    pub count: VarInt,
    pub addr_list: Vec<NetAddr>,
}

impl AddrPayload {
    /// Parse an addr payload from `bytes`, returning the parsed value and bytes consumed.
    pub fn parse(bytes: &[u8]) -> (AddrPayload, usize) {
        let (count, mut offset) = VarInt::parse(bytes);
        let count_val = count.value as usize;
        let mut addr_list = Vec::with_capacity(count_val);
        for _ in 0..count_val {
            let (na, consumed) = NetAddr::parse(&bytes[offset..], true);
            addr_list.push(na);
            offset += consumed;
        }
        (AddrPayload { count, addr_list }, offset)
    }
}
