// message/endianness.rs

/// Read a little-endian u16 from a byte slice.
pub fn read_u16_le(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[0], buf[1]])
}

/// Read a big-endian u16 from a byte slice.
pub fn read_u16_be(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

/// Read a little-endian u32 from a byte slice.
pub fn read_u32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Read a little-endian i32 from a byte slice.
pub fn read_i32_le(buf: &[u8]) -> i32 {
    i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Read a little-endian u64 from a byte slice.
pub fn read_u64_le(buf: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[..8]);
    u64::from_le_bytes(bytes)
}

/// Read a little-endian i64 from a byte slice.
pub fn read_i64_le(buf: &[u8]) -> i64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[..8]);
    i64::from_le_bytes(bytes)
}

/// Write a little-endian u16 into a byte slice.
pub fn write_u16_le(buf: &mut [u8], v: u16) {
    buf[..2].copy_from_slice(&v.to_le_bytes());
}

/// Write a big-endian u16 into a byte slice.
pub fn write_u16_be(buf: &mut [u8], v: u16) {
    buf[..2].copy_from_slice(&v.to_be_bytes());
}

/// Write a little-endian u32 into a byte slice.
pub fn write_u32_le(buf: &mut [u8], v: u32) {
    buf[..4].copy_from_slice(&v.to_le_bytes());
}

/// Write a little-endian i32 into a byte slice.
pub fn write_i32_le(buf: &mut [u8], v: i32) {
    buf[..4].copy_from_slice(&v.to_le_bytes());
}

/// Write a little-endian u64 into a byte slice.
pub fn write_u64_le(buf: &mut [u8], v: u64) {
    buf[..8].copy_from_slice(&v.to_le_bytes());
}

/// Write a little-endian i64 into a byte slice.
pub fn write_i64_le(buf: &mut [u8], v: i64) {
    buf[..8].copy_from_slice(&v.to_le_bytes());
}
