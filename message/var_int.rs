// message/var_int.rs

use crate::message::bytes::Bytes;
use crate::message::endianness::*;

/// Bitcoin-style variable-length integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt {
    pub value: u64,
}

impl VarInt {
    pub fn serialize(&self) -> Bytes {
        let mut buf = Vec::new();
        if self.value < 0xFD {
            buf.push(self.value as u8);
        } else if self.value <= 0xFFFF {
            buf.push(0xFD);
            buf.extend_from_slice(&(self.value as u16).to_le_bytes());
        } else if self.value <= 0xFFFFFFFF {
            buf.push(0xFE);
            buf.extend_from_slice(&(self.value as u32).to_le_bytes());
        } else {
            buf.push(0xFF);
            buf.extend_from_slice(&self.value.to_le_bytes());
        }
        buf
    }

    /// Parse a varint from `bytes`, returning the parsed value and how many bytes were consumed.
    pub fn parse(bytes: &[u8]) -> (VarInt, usize) {
        let first = bytes[0];
        if first < 0xFD {
            (VarInt { value: first as u64 }, 1)
        } else if first == 0xFD {
            let value = read_u16_le(&bytes[1..3]) as u64;
            (VarInt { value }, 3)
        } else if first == 0xFE {
            let value = read_u32_le(&bytes[1..5]) as u64;
            (VarInt { value }, 5)
        } else {
            let value = read_u64_le(&bytes[1..9]);
            (VarInt { value }, 9)
        }
    }
}

