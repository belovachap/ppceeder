// message/var_str.rs

use crate::message::bytes::Bytes;
use crate::message::var_int::VarInt;

/// Variable-length string: varint length prefix followed by UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarStr {
    pub length: VarInt,
    pub string: String,
}

impl VarStr {
    pub fn new(string: String) -> Self {
        let length = VarInt {
            value: string.len() as u64,
        };
        VarStr { length, string }
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = self.length.serialize();
        buf.extend_from_slice(self.string.as_bytes());
        buf
    }

    /// Parse a var_str from `bytes`, returning the parsed value and bytes consumed.
    pub fn parse(bytes: &[u8]) -> (VarStr, usize) {
        let (length, var_int_bytes) = VarInt::parse(bytes);
        let str_len = length.value as usize;
        let string = String::from_utf8_lossy(
            &bytes[var_int_bytes..var_int_bytes + str_len],
        )
        .into_owned();
        (
            VarStr { length, string },
            var_int_bytes + str_len,
        )
    }
}
