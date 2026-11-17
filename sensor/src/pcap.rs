//! Streaming pcap / pcapng reader (Ethernet link type only), reusing one frame buffer.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

pub const LINKTYPE_ETHERNET: u32 = 1;

#[derive(Debug, Default, Clone, Copy)]
pub struct ReadStats {
    pub frames: u64,
    pub skipped: u64,
}

fn read_exact_or_eof(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 if filled == 0 => return Ok(false),
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated capture file")),
            n => filled += n,
        }
    }
    Ok(true)
}

/// Calls `on_frame(data, ts_ms)` for every Ethernet frame in a pcap or pcapng file.
pub fn read_file(path: &Path, mut on_frame: impl FnMut(&[u8], i64)) -> io::Result<ReadStats> {
    let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?);
    let mut magic = [0u8; 4];
    if !read_exact_or_eof(&mut reader, &mut magic)? {
        return Ok(ReadStats::default());
    }
    match magic {
        [0x0A, 0x0D, 0x0D, 0x0A] => read_pcapng(&mut reader, magic, &mut on_frame),
        _ => read_pcap(&mut reader, magic, &mut on_frame),
    }
}

fn read_pcap(r: &mut impl Read, magic: [u8; 4], on_frame: &mut impl FnMut(&[u8], i64)) -> io::Result<ReadStats> {
    let (swap, nanos) = match u32::from_le_bytes(magic) {
        0xA1B2C3D4 => (false, false),
        0xA1B23C4D => (false, true),
        0xD4C3B2A1 => (true, false),
        0x4D3CB2A1 => (true, true),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "not a pcap or pcapng file")),
    };
    let u32_at = |b: &[u8], o: usize| {
        let v = [b[o], b[o + 1], b[o + 2], b[o + 3]];
        if swap { u32::from_be_bytes(v) } else { u32::from_le_bytes(v) }
    };
    let mut header = [0u8; 20];
    r.read_exact(&mut header)?;
    let linktype = u32_at(&header, 16) & 0x0FFF_FFFF;
    let mut stats = ReadStats::default();
    let mut rec = [0u8; 16];
    let mut buf = vec![0u8; 65536];
    while read_exact_or_eof(r, &mut rec)? {
        let (sec, frac, incl) = (u32_at(&rec, 0) as i64, u32_at(&rec, 4) as i64, u32_at(&rec, 8) as usize);
        if incl > 256 * 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt pcap record length"));
        }
        if buf.len() < incl {
            buf.resize(incl, 0);
        }
        r.read_exact(&mut buf[..incl])?;
        if linktype != LINKTYPE_ETHERNET {
            stats.skipped += 1;
            continue;
        }
        let ms = sec * 1000 + if nanos { frac / 1_000_000 } else { frac / 1000 };
        on_frame(&buf[..incl], ms);
        stats.frames += 1;
    }
    Ok(stats)
}

struct Interface {
    linktype: u32,
    /// timestamp units per second
    resolution: u64,
}

fn read_pcapng(r: &mut impl Read, first: [u8; 4], on_frame: &mut impl FnMut(&[u8], i64)) -> io::Result<ReadStats> {
    let mut stats = ReadStats::default();
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut big_endian = false;
    let mut block = vec![0u8; 65536];
    let mut pending_type = Some(first);
    loop {
        let mut head = [0u8; 8];
        match pending_type.take() {
            Some(t) => {
                head[..4].copy_from_slice(&t);
                r.read_exact(&mut head[4..])?;
            }
            None => {
                if !read_exact_or_eof(r, &mut head)? {
                    break;
                }
            }
        }
        let raw_type = [head[0], head[1], head[2], head[3]];
        if raw_type == [0x0A, 0x0D, 0x0D, 0x0A] {
            // Section header: the byte-order magic follows the length field.
            let mut bom = [0u8; 4];
            r.read_exact(&mut bom)?;
            big_endian = bom == [0x1A, 0x2B, 0x3C, 0x4D];
            interfaces.clear();
            let len = if big_endian { u32::from_be_bytes([head[4], head[5], head[6], head[7]]) }
                      else { u32::from_le_bytes([head[4], head[5], head[6], head[7]]) } as usize;
            if len < 12 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt pcapng section"));
            }
            skip(r, len - 12)?;
            continue;
        }
        let u32_of = |b: [u8; 4]| if big_endian { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) };
        let btype = u32_of(raw_type);
        let len = u32_of([head[4], head[5], head[6], head[7]]) as usize;
        if !(12..=256 * 1024 * 1024).contains(&len) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt pcapng block length"));
        }
        let body_len = len - 8;
        if block.len() < body_len {
            block.resize(body_len, 0);
        }
        r.read_exact(&mut block[..body_len])?;
        let body = &block[..body_len - 4]; // trailing length copy
        let rd32 = |o: usize| body.get(o..o + 4).map(|b| u32_of([b[0], b[1], b[2], b[3]]));
        let rd16 = |o: usize| body.get(o..o + 2).map(|b| if big_endian { u16::from_be_bytes([b[0], b[1]]) }
                                                         else { u16::from_le_bytes([b[0], b[1]]) });
        match btype {
            1 => {
                let linktype = rd16(0).unwrap_or(0) as u32;
                let mut resolution = 1_000_000u64;
                let mut o = 8;
                while let (Some(code), Some(olen)) = (rd16(o), rd16(o + 2)) {
                    if code == 0 {
                        break;
                    }
                    if code == 9 && olen >= 1 {
                        let v = body[o + 4];
                        resolution = if v & 0x80 != 0 { 1u64 << (v & 0x7F).min(63) } else { 10u64.pow((v as u32).min(18)) };
                    }
                    o += 4 + (olen as usize).div_ceil(4) * 4;
                }
                interfaces.push(Interface { linktype, resolution });
            }
            6 => {
                let (Some(iface), Some(hi), Some(lo), Some(cap)) = (rd32(0), rd32(4), rd32(8), rd32(12)) else { continue };
                let Some(info) = interfaces.get(iface as usize) else { stats.skipped += 1; continue };
                let data = body.get(20..20 + cap as usize).unwrap_or(&body[20.min(body.len())..]);
                if info.linktype != LINKTYPE_ETHERNET {
                    stats.skipped += 1;
                    continue;
                }
                let ts = ((hi as u64) << 32) | lo as u64;
                let ms = (ts as u128 * 1000 / info.resolution as u128) as i64;
                on_frame(data, ms);
                stats.frames += 1;
            }
            3 => {
                // Simple packet block: no timestamp, interface 0.
                if interfaces.first().is_some_and(|i| i.linktype == LINKTYPE_ETHERNET) {
                    on_frame(body.get(4..).unwrap_or(&[]), 0);
                    stats.frames += 1;
                } else {
                    stats.skipped += 1;
                }
            }
            _ => {}
        }
    }
    Ok(stats)
}

fn skip(r: &mut impl Read, n: usize) -> io::Result<()> {
    io::copy(&mut r.take(n as u64), &mut io::sink())?;
    Ok(())
}
