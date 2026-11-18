// message/message.rs

use crate::message::bytes::Bytes;
use crate::message::endianness::*;
use std::io::{Read, Write};
use std::net::TcpStream;

const MAGIC: u32 = 0xE5E9E8E6;
const HEADER_LENGTH: usize = 24; // magic(4) + command(12) + length(4) + checksum(4)
const MAX_PAYLOAD_LENGTH: u32 = 2 * 1024 * 1024; // 2 MB

/// A framed protocol message.
#[derive(Debug, Clone)]
pub struct Message {
    pub magic: u32,
    pub command: [u8; 12],
    pub length: u32,
    pub checksum: u32,
    pub payload: Bytes,
}

impl Message {
    pub fn new(command: &str, payload: Bytes) -> Self {
        let mut cmd = [0u8; 12];
        let len = command.len().min(12);
        cmd[..len].copy_from_slice(&command.as_bytes()[..len]);

        let checksum = sha256_double(&payload);

        Message {
            magic: MAGIC,
            command: cmd,
            length: payload.len() as u32,
            checksum,
            payload,
        }
    }

    pub fn serialize(&self) -> Bytes {
        let mut buf = Vec::with_capacity(HEADER_LENGTH + self.payload.len());
        buf.extend_from_slice(&self.magic.to_le_bytes());
        buf.extend_from_slice(&self.command);
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.checksum.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse a message from a byte slice.
    pub fn parse(bytes: &[u8]) -> (Message, usize) {
        let magic = read_u32_le(&bytes[0..4]);
        let mut command = [0u8; 12];
        command.copy_from_slice(&bytes[4..16]);
        let length = read_u32_le(&bytes[16..20]);
        let checksum = read_u32_le(&bytes[20..24]);
        let payload = if length > 0 {
            bytes[HEADER_LENGTH..HEADER_LENGTH + length as usize].to_vec()
        } else {
            Vec::new()
        };
        (
            Message {
                magic,
                command,
                length,
                checksum,
                payload,
            },
            HEADER_LENGTH + length as usize,
        )
    }

    /// Read a message from a TCP stream.
    pub fn read(stream: &mut TcpStream) -> std::io::Result<Message> {
        let mut header = [0u8; HEADER_LENGTH];
        stream.read_exact(&mut header)?;

        let magic = read_u32_le(&header[0..4]);
        let mut command = [0u8; 12];
        command.copy_from_slice(&header[4..16]);
        let length = read_u32_le(&header[16..20]);
        let checksum = read_u32_le(&header[20..24]);

        if magic != MAGIC || length > MAX_PAYLOAD_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid magic or payload too large",
            ));
        }

        let payload = if length > 0 {
            let mut buf = vec![0u8; length as usize];
            stream.read_exact(&mut buf)?;
            buf
        } else {
            Vec::new()
        };

        Ok(Message {
            magic,
            command,
            length,
            checksum,
            payload,
        })
    }

    /// Write a message to a TCP stream.
    pub fn write(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let bytes = self.serialize();
        stream.write_all(&bytes)?;
        Ok(())
    }
}

/// Double-SHA256 checksum (first 4 bytes).
fn sha256_double(data: &[u8]) -> u32 {
    use openssl::sha::sha256;
    let first = sha256(data);
    let second = sha256(&first);
    u32::from_le_bytes([second[0], second[1], second[2], second[3]])
}
