//! Protocol dispatch: ethertype, well-known server port, port-only signatures, then payload content.

pub mod base;
pub mod enip;
pub mod iso_tsap;
pub mod layer2;
pub mod misc;
pub mod modbus;
pub mod power;

pub use base::Finding;

use crate::decode::{Frame, Transport};

type Handler = fn(&[u8], bool, &mut Vec<Finding>);

fn tcp_handler(port: u16) -> Option<Handler> {
    Some(match port {
        modbus::PORT => modbus::dissect,
        iso_tsap::PORT => iso_tsap::dissect,
        enip::PORT => enip::dissect,
        power::DNP3_PORT => power::dissect_dnp3,
        power::IEC104_PORT => power::dissect_iec104,
        4840 => |p, t, o| { misc::opcua(p, t, o); },
        _ => return None,
    })
}

fn udp_handler(port: u16) -> Option<Handler> {
    Some(match port {
        enip::PORT => enip::dissect,
        power::DNP3_PORT => power::dissect_dnp3,
        47808 => misc::bacnet,
        _ => return None,
    })
}

/// Appends the findings for one frame to `out` (cleared first). Stateless and thread-safe.
pub fn dissect(frame: &Frame, out: &mut Vec<Finding>) {
    out.clear();
    if frame.transport == Transport::None {
        layer2::dissect(frame.ethertype, frame.payload, out);
        return;
    }
    let is_tcp = match frame.transport {
        Transport::Tcp => true,
        Transport::Udp => false,
        _ => return,
    };
    if frame.payload.is_empty() {
        return;
    }
    let table = if is_tcp { tcp_handler } else { udp_handler };
    for (port, to_server) in [(frame.dst_port, true), (frame.src_port, false)] {
        if let Some(handler) = table(port) {
            handler(frame.payload, to_server, out);
            return;
        }
    }
    if !is_tcp && (frame.src_port == enip::IO_PORT || frame.dst_port == enip::IO_PORT) {
        enip::dissect_io(out);
        return;
    }
    for (port, to_server) in [(frame.dst_port, true), (frame.src_port, false)] {
        if let Some(sig) = misc::port_signature(is_tcp, port) {
            misc::port_only(sig, to_server, out);
            return;
        }
    }
    // Unknown ports: content signatures; direction guessed from port numbers.
    let to_server = frame.dst_port < frame.src_port;
    if !misc::slmp(frame.payload, to_server, out) {
        misc::opcua(frame.payload, to_server, out);
    }
}

/// Decode a read response against the request items it answers (appends measured values to `out`).
pub fn decode_read(items: &[base::ReadItem], data: &base::ReadData, out: &mut Finding) {
    match data {
        base::ReadData::Modbus { bytes } => {
            if let Some(item) = items.first() {
                modbus::decode_read(item, bytes, out);
            }
        }
        base::ReadData::S7 { items: payloads } => {
            for (item, payload) in items.iter().zip(payloads) {
                if let Some(payload) = payload {
                    iso_tsap::decode_read(item, payload, out);
                }
            }
        }
        base::ReadData::Cip { items: payloads } => {
            for (item, payload) in items.iter().zip(payloads) {
                if let Some(payload) = payload {
                    enip::decode_read(item, payload, out);
                }
            }
        }
    }
}
