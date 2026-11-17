//! Live passive capture through libpcap (Linux) / Npcap (Windows), loaded at runtime so building
//! needs no SDK and a sensor without a capture driver still runs (PCAP import only).

use libloading::{Library, Symbol};
use std::ffi::{c_char, c_int, c_long, c_uint, CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[repr(C)]
struct TimeVal {
    tv_sec: c_long,
    tv_usec: c_long,
}

#[repr(C)]
struct PktHdr {
    ts: TimeVal,
    caplen: c_uint,
    len: c_uint,
}

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut std::ffi::c_void,
    flags: c_uint,
}

type Pcap = std::ffi::c_void;
const ERRBUF: usize = 256;

fn library() -> Result<Library, String> {
    let candidates: &[&str] = if cfg!(windows) {
        &["C:\\Windows\\System32\\Npcap\\wpcap.dll", "wpcap.dll"]
    } else if cfg!(target_os = "macos") {
        &["libpcap.dylib", "libpcap.A.dylib"]
    } else {
        &["libpcap.so.1", "libpcap.so", "libpcap.so.0.8"]
    };
    let mut last = String::new();
    for name in candidates {
        // SAFETY: loading the system packet-capture library; its initializers are trusted.
        match unsafe { Library::new(*name) } {
            Ok(lib) => return Ok(lib),
            Err(e) => last = e.to_string(),
        }
    }
    Err(if cfg!(windows) {
        format!("Npcap이 설치되어 있지 않습니다 (https://npcap.com): {last}")
    } else {
        format!("libpcap을 찾을 수 없습니다 (libpcap 패키지 설치 필요): {last}")
    })
}

pub struct Device {
    pub name: String,
    pub description: String,
}

pub fn list_devices() -> Result<Vec<Device>, String> {
    let lib = library()?;
    // SAFETY: symbol signatures follow the documented libpcap C API.
    unsafe {
        let findall: Symbol<unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int> =
            lib.get(b"pcap_findalldevs\0").map_err(|e| e.to_string())?;
        let freeall: Symbol<unsafe extern "C" fn(*mut PcapIf)> = lib.get(b"pcap_freealldevs\0").map_err(|e| e.to_string())?;
        let mut errbuf = [0 as c_char; ERRBUF];
        let mut head: *mut PcapIf = std::ptr::null_mut();
        if findall(&mut head, errbuf.as_mut_ptr()) != 0 {
            return Err(CStr::from_ptr(errbuf.as_ptr()).to_string_lossy().into_owned());
        }
        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            let d = &*cur;
            let text = |p: *mut c_char| if p.is_null() { String::new() } else { CStr::from_ptr(p).to_string_lossy().into_owned() };
            out.push(Device { name: text(d.name), description: text(d.description) });
            cur = d.next;
        }
        freeall(head);
        Ok(out)
    }
}

/// Opens `interface` and calls `on_packet(data, ts_ms)` until `stop` is set or an error occurs.
/// `on_idle` runs whenever the read times out, so callers can flush batches.
pub fn capture(interface: &str, stop: Arc<AtomicBool>, ready: impl FnOnce(Result<(), String>),
               mut on_packet: impl FnMut(&[u8], i64), mut on_idle: impl FnMut()) {
    let lib = match library() {
        Ok(lib) => lib,
        Err(e) => return ready(Err(e)),
    };
    // SAFETY: libpcap C API; the packet pointer is only used before the next pcap_next_ex call.
    unsafe {
        macro_rules! sym {
            ($name:literal, $t:ty) => {
                match lib.get::<$t>(concat!($name, "\0").as_bytes()) {
                    Ok(s) => s,
                    Err(e) => return ready(Err(e.to_string())),
                }
            };
        }
        let create = sym!("pcap_create", unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut Pcap);
        let set_snaplen = sym!("pcap_set_snaplen", unsafe extern "C" fn(*mut Pcap, c_int) -> c_int);
        let set_promisc = sym!("pcap_set_promisc", unsafe extern "C" fn(*mut Pcap, c_int) -> c_int);
        let set_timeout = sym!("pcap_set_timeout", unsafe extern "C" fn(*mut Pcap, c_int) -> c_int);
        let set_buffer = sym!("pcap_set_buffer_size", unsafe extern "C" fn(*mut Pcap, c_int) -> c_int);
        let activate = sym!("pcap_activate", unsafe extern "C" fn(*mut Pcap) -> c_int);
        let geterr = sym!("pcap_geterr", unsafe extern "C" fn(*mut Pcap) -> *const c_char);
        let next_ex = sym!("pcap_next_ex", unsafe extern "C" fn(*mut Pcap, *mut *mut PktHdr, *mut *const u8) -> c_int);
        let close = sym!("pcap_close", unsafe extern "C" fn(*mut Pcap));

        let Ok(device) = CString::new(interface) else { return ready(Err("invalid interface name".into())) };
        let mut errbuf = [0 as c_char; ERRBUF];
        let handle = create(device.as_ptr(), errbuf.as_mut_ptr());
        if handle.is_null() {
            return ready(Err(CStr::from_ptr(errbuf.as_ptr()).to_string_lossy().into_owned()));
        }
        set_snaplen(handle, 65535);
        set_promisc(handle, 1);
        set_timeout(handle, 100);
        set_buffer(handle, 64 * 1024 * 1024); // large kernel ring: absorbs bursts without drops
        if activate(handle) < 0 {
            let msg = CStr::from_ptr(geterr(handle)).to_string_lossy().into_owned();
            close(handle);
            return ready(Err(msg));
        }
        ready(Ok(()));
        while !stop.load(Ordering::Relaxed) {
            let mut hdr: *mut PktHdr = std::ptr::null_mut();
            let mut data: *const u8 = std::ptr::null();
            match next_ex(handle, &mut hdr, &mut data) {
                1 => {
                    let h = &*hdr;
                    let packet = std::slice::from_raw_parts(data, h.caplen as usize);
                    let ms = h.ts.tv_sec as i64 * 1000 + h.ts.tv_usec as i64 / 1000;
                    on_packet(packet, ms);
                }
                0 => on_idle(),
                _ => break,
            }
        }
        close(handle);
    }
}
