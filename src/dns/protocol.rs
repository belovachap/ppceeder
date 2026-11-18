use std::sync::Arc;
use std::sync::atomic::AtomicU64;

pub const CLASS_IN: u16 = 1;
pub const QCLASS_ANY: u16 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Mx = 15,
    Aaaa = 28,
    Srv = 33,
    Any = 255,
}

impl DnsType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::A),
            2 => Some(Self::Ns),
            5 => Some(Self::Cname),
            6 => Some(Self::Soa),
            15 => Some(Self::Mx),
            28 => Some(Self::Aaaa),
            33 => Some(Self::Srv),
            255 => Some(Self::Any),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum Addr {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub struct DnsOpt {
    pub port: u16,
    pub datattl: u32,
    pub nsttl: u32,
    pub host: String,
    pub ns: String,
    pub mbox: Option<String>,
    pub cb: Box<dyn Fn(&DnsOpt, &mut Vec<Addr>, bool, bool) -> usize>,
    pub n_requests: Arc<AtomicU64>,
}

/// Parse a DNS name from wire format, handling compression pointers.
/// Returns (name_string, bytes_consumed) or an error code.
fn parse_name(
    inbuf: &[u8],
    inend: &[u8],
    inpos: &mut usize,
) -> Result<String, i32> {
    let mut buf = String::new();
    let mut init = true;

    loop {
        if *inpos >= inend.len() {
            return Err(-1);
        }
        let octet = inbuf[*inpos] as i32;
        *inpos += 1;

        if octet == 0 {
            return Ok(buf);
        }

        if !init {
            buf.push('.');
        } else {
            init = false;
        }

        // Compression pointer
        if (octet & 0xC0) == 0xC0 {
            if *inpos >= inend.len() {
                return Err(-1);
            }
            let ref_offset = ((octet - 0xC0) << 8) + inbuf[*inpos] as i32;
            *inpos += 1;
            if ref_offset < 0 || ref_offset as usize >= *inpos - 2 {
                return Err(-1);
            }
            let mut ref_pos = ref_offset as usize;
            let sub = parse_name(inbuf, inend, &mut ref_pos)?;
            buf.push_str(&sub);
            return Ok(buf);
        }

        if octet > 63 {
            return Err(-1);
        }

        let len = octet as usize;
        if *inpos + len > inend.len() {
            return Err(-1);
        }
        for _ in 0..len {
            let c = inbuf[*inpos];
            *inpos += 1;
            if c == b'.' {
                return Err(-1);
            }
            buf.push(c as char);
        }
    }
}

/// Write a DNS name in wire format. If `offset >= 0`, use a compression pointer.
fn write_name(out: &mut Vec<u8>, name: &str, offset: i32) -> Result<(), i32> {
    let mut remaining = name;
    let mut first = true;

    while !remaining.is_empty() {
        let dot_pos = remaining.find('.');
        let (label, rest) = match dot_pos {
            Some(i) => (&remaining[..i], &remaining[i + 1..]),
            None => (remaining, ""),
        };

        if label.len() > 63 {
            return Err(-1);
        }
        if label.is_empty() {
            return Err(-3);
        }

        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());

        if dot_pos.is_none() {
            break;
        }
        remaining = rest;
        let _ = first;
        first = false;
    }

    if offset < 0 {
        out.push(0);
    } else {
        out.push(((offset >> 8) as u8) | 0xC0);
        out.push((offset & 0xFF) as u8);
    }

    Ok(())
}

fn write_record_header(
    out: &mut Vec<u8>,
    name: &str,
    offset: i32,
    typ: DnsType,
    cls: u16,
    ttl: u32,
) -> Result<(), i32> {
    write_name(out, name, offset)?;
    let t = typ as u16;
    out.push((t >> 8) as u8);
    out.push((t & 0xFF) as u8);
    out.push((cls >> 8) as u8);
    out.push((cls & 0xFF) as u8);
    out.push((ttl >> 24) as u8);
    out.push((ttl >> 16) as u8);
    out.push((ttl >> 8) as u8);
    out.push((ttl & 0xFF) as u8);
    Ok(())
}

fn write_record_a(out: &mut Vec<u8>, name: &str, offset: i32, cls: u16, ttl: u32, ip: &[u8; 4]) -> Result<(), i32> {
    let start = out.len();
    write_record_header(out, name, offset, DnsType::A, cls, ttl)?;
    // rdlength = 4
    out.push(0);
    out.push(4);
    out.extend_from_slice(ip);
    let _ = start;
    Ok(())
}

fn write_record_aaaa(out: &mut Vec<u8>, name: &str, offset: i32, cls: u16, ttl: u32, ip: &[u8; 16]) -> Result<(), i32> {
    let start = out.len();
    write_record_header(out, name, offset, DnsType::Aaaa, cls, ttl)?;
    // rdlength = 16
    out.push(0);
    out.push(16);
    out.extend_from_slice(ip);
    let _ = start;
    Ok(())
}

fn write_record_ns(out: &mut Vec<u8>, name: &str, offset: i32, cls: u16, ttl: u32, ns: &str) -> Result<(), i32> {
    let start = out.len();
    write_record_header(out, name, offset, DnsType::Ns, cls, ttl)?;
    // placeholder rdlength
    let rdlen_pos = out.len();
    out.push(0);
    out.push(0);
    let rdata_start = out.len();
    write_name(out, ns, -1)?;
    let rdlen = (out.len() - rdata_start) as u16;
    out[rdlen_pos] = (rdlen >> 8) as u8;
    out[rdlen_pos + 1] = (rdlen & 0xFF) as u8;
    let _ = start;
    Ok(())
}

fn write_record_soa(
    out: &mut Vec<u8>,
    name: &str,
    offset: i32,
    cls: u16,
    ttl: u32,
    mname: &str,
    rname: &str,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
) -> Result<(), i32> {
    let start = out.len();
    write_record_header(out, name, offset, DnsType::Soa, cls, ttl)?;
    let rdlen_pos = out.len();
    out.push(0);
    out.push(0);
    let rdata_start = out.len();

    write_name(out, mname, -1)?;
    write_name(out, rname, -1)?;

    for val in [serial, refresh, retry, expire, minimum] {
        out.push((val >> 24) as u8);
        out.push((val >> 16) as u8);
        out.push((val >> 8) as u8);
        out.push((val & 0xFF) as u8);
    }

    let rdlen = (out.len() - rdata_start) as u16;
    out[rdlen_pos] = (rdlen >> 8) as u8;
    out[rdlen_pos + 1] = (rdlen & 0xFF) as u8;
    let _ = start;
    Ok(())
}

/// Handle a single DNS query and produce a response.
/// Returns the response bytes, or an error code.
pub fn dns_handle(opt: &DnsOpt, inbuf: &[u8]) -> Result<Vec<u8>, i32> {
    if inbuf.len() < 12 {
        return Err(-1);
    }

    let mut outbuf: Vec<u8> = Vec::with_capacity(512);

    // Copy ID
    outbuf.push(inbuf[0]);
    outbuf.push(inbuf[1]);

    // Copy flags, clear error bits
    let mut flags1 = inbuf[2];
    let mut flags2 = inbuf[3] & !15;

    // Check QR (must be query)
    if inbuf[2] & 128 != 0 {
        return Err(1);
    }
    // Check opcode
    if ((inbuf[2] & 120) >> 3) != 0 {
        return Err(4);
    }

    // Unset TC and RA
    flags1 &= !2;
    flags2 &= !128;

    outbuf.push(flags1);
    outbuf.push(flags2);

    // Check question count
    let nquestion = ((inbuf[4] as u16) << 8) | inbuf[5] as u16;
    if nquestion == 0 {
        return Err(0);
    }
    if nquestion > 1 {
        return Err(4);
    }

    let mut inpos: usize = 12;
    let inend_len = inbuf.len();

    let name = parse_name(inbuf, &inbuf[..inend_len], &mut inpos).map_err(|_| 1i32)?;

    // Validate name matches opt.host (case-insensitive, allow trailing dot)
    let host_lower = opt.host.to_lowercase();
    let name_lower = name.to_lowercase();
    let name_stripped = name_lower.strip_suffix('.').unwrap_or(&name_lower);
    if name_stripped != host_lower {
        return Err(5);
    }

    if inend_len - inpos < 4 {
        return Err(1);
    }

    let typ_raw = ((inbuf[inpos] as u16) << 8) | inbuf[inpos + 1] as u16;
    let cls = ((inbuf[inpos + 2] as u16) << 8) | inbuf[inpos + 3] as u16;
    inpos += 4;

    let typ = DnsType::from_u16(typ_raw).unwrap_or(DnsType::Any);

    // Set QR
    outbuf[2] |= 128;

    // Copy question section
    let qstart = 12;
    let qend = inpos;
    outbuf.extend_from_slice(&inbuf[qstart..qend]);

    // Set counts: 1 question, 0 answers, 0 authority, 0 additional
    outbuf.push(0); outbuf.push(1); // QDCOUNT
    outbuf.push(0); outbuf.push(0); // ANCOUNT
    outbuf.push(0); outbuf.push(0); // NSCOUNT
    outbuf.push(0); outbuf.push(0); // ARCOUNT

    let offset = qstart as i32;
    let mut ancount: u8 = 0;
    let mut nscount: u8 = 0;
    let mut have_ns = false;

    // Answer section
    if (typ == DnsType::Ns || typ == DnsType::Any) && (cls == CLASS_IN || cls == QCLASS_ANY) {
        let mut tmp: Vec<u8> = Vec::new();
        if write_record_ns(&mut tmp, "", offset, CLASS_IN, opt.nsttl, &opt.ns).is_ok() {
            outbuf.extend_from_slice(&tmp);
            ancount += 1;
            have_ns = true;
        }
    }

    if (typ == DnsType::Soa || typ == DnsType::Any) && (cls == CLASS_IN || cls == QCLASS_ANY) {
        if let Some(ref mbox) = opt.mbox {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let mut tmp: Vec<u8> = Vec::new();
            if write_record_soa(
                &mut tmp, "", offset, CLASS_IN, opt.nsttl,
                &opt.ns, mbox, now, 604800, 86400, 2592000, 604800,
            ).is_ok() {
                outbuf.extend_from_slice(&tmp);
                ancount += 1;
            }
        }
    }

    if (typ == DnsType::A || typ == DnsType::Aaaa || typ == DnsType::Any)
        && (cls == CLASS_IN || cls == QCLASS_ANY)
    {
        let want_v4 = typ == DnsType::A || typ == DnsType::Any;
        let want_v6 = typ == DnsType::Aaaa || typ == DnsType::Any;
        let mut addrs: Vec<Addr> = Vec::new();
        let naddr = (opt.cb)(opt, &mut addrs, want_v4, want_v6);
        let mut n = 0;
        while n < naddr {
            let mut tmp: Vec<u8> = Vec::new();
            let ret = match &addrs[n] {
                Addr::V4(ip) => write_record_a(&mut tmp, "", offset, CLASS_IN, opt.datattl, ip),
                Addr::V6(ip) => write_record_aaaa(&mut tmp, "", offset, CLASS_IN, opt.datattl, ip),
            };
            if ret.is_ok() {
                outbuf.extend_from_slice(&tmp);
                ancount += 1;
                n += 1;
            } else {
                break;
            }
        }
    }

    // Authority section
    if !have_ns {
        let mut tmp: Vec<u8> = Vec::new();
        if write_record_ns(&mut tmp, "", offset, CLASS_IN, opt.nsttl, &opt.ns).is_ok() {
            outbuf.extend_from_slice(&tmp);
            nscount += 1;
        }
    }

    // Set AA flag
    outbuf[2] |= 4;

    // Patch counts
    outbuf[4] = 0; outbuf[5] = 1; // QDCOUNT = 1
    outbuf[6] = 0; outbuf[7] = ancount;
    outbuf[8] = 0; outbuf[9] = nscount;
    outbuf[10] = 0; outbuf[11] = 0;

    Ok(outbuf)
}

