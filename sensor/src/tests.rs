//! Behavioural tests, ported from the original Python suite (backend/tests).

use crate::baseline::Mode;
use crate::engine::Engine;
use crate::storage::Store;
use crate::vulns::VulnDb;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

const PLC_MAC: &str = "00:1b:1b:00:00:10";
const HMI_MAC: &str = "00:0c:29:00:00:20";
const T0: i64 = 1_700_000_000_000;

fn mac(s: &str) -> Vec<u8> {
    s.split(':').map(|h| u8::from_str_radix(h, 16).unwrap()).collect()
}
fn ip(s: &str) -> Vec<u8> {
    s.split('.').map(|p| p.parse::<u8>().unwrap()).collect()
}
fn ether(dst: &str, src: &str, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    [mac(dst), mac(src), ethertype.to_be_bytes().to_vec(), payload.to_vec()].concat()
}
fn ipv4(src: &str, dst: &str, proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut h = vec![0x45, 0];
    h.extend(((20 + l4.len()) as u16).to_be_bytes());
    h.extend([0, 1, 0, 0, 64, proto, 0, 0]);
    h.extend(ip(src));
    h.extend(ip(dst));
    [h, l4.to_vec()].concat()
}
#[allow(clippy::too_many_arguments)]
fn tcp_full(src: &str, dst: &str, sport: u16, dport: u16, payload: &[u8], smac: &str, dmac: &str, flags: u8) -> Vec<u8> {
    let mut seg = Vec::new();
    seg.extend(sport.to_be_bytes());
    seg.extend(dport.to_be_bytes());
    seg.extend([0, 0, 0, 1, 0, 0, 0, 1, 5 << 4, flags, 0x20, 0, 0, 0, 0, 0]);
    seg.extend(payload);
    ether(dmac, smac, 0x0800, &ipv4(src, dst, 6, &seg))
}
fn tcp(src: &str, dst: &str, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    tcp_full(src, dst, sport, dport, payload, HMI_MAC, PLC_MAC, 0x18)
}
fn tcp_rev(src: &str, dst: &str, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    tcp_full(src, dst, sport, dport, payload, PLC_MAC, HMI_MAC, 0x18)
}
fn udp_full(src: &str, dst: &str, sport: u16, dport: u16, payload: &[u8], smac: &str, dmac: &str) -> Vec<u8> {
    let mut seg = Vec::new();
    seg.extend(sport.to_be_bytes());
    seg.extend(dport.to_be_bytes());
    seg.extend(((8 + payload.len()) as u16).to_be_bytes());
    seg.extend([0, 0]);
    seg.extend(payload);
    ether(dmac, smac, 0x0800, &ipv4(src, dst, 17, &seg))
}
fn mbap(unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut v = vec![0, 1, 0, 0];
    v.extend(((pdu.len() + 1) as u16).to_be_bytes());
    v.push(unit);
    v.extend(pdu);
    v
}
fn tpkt_cotp(s7: &[u8]) -> Vec<u8> {
    let body = [&[0x02, 0xF0, 0x80][..], s7].concat();
    [vec![3, 0], ((4 + body.len()) as u16).to_be_bytes().to_vec(), body].concat()
}
fn s7_header(rosctr: u8, pdu_ref: u16, params: &[u8], data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x32, rosctr, 0, 0];
    v.extend(pdu_ref.to_be_bytes());
    v.extend((params.len() as u16).to_be_bytes());
    v.extend((data.len() as u16).to_be_bytes());
    [v, params.to_vec(), data.to_vec()].concat()
}

fn feed(engine: &mut Engine, frames: &[Vec<u8>], start: i64) {
    for (i, f) in frames.iter().enumerate() {
        engine.process_raw(f, start + i as i64 * 1000);
    }
}
fn snap(engine: &mut Engine) -> Value {
    serde_json::from_str(&engine.snapshot_json(T0)).unwrap()
}
fn run(frames: &[Vec<u8>]) -> Value {
    let mut engine = Engine::new();
    feed(&mut engine, frames, T0);
    snap(&mut engine)
}
fn by_label(s: &Value) -> HashMap<String, Value> {
    s["assets"].as_array().unwrap().iter().map(|a| (a["label"].as_str().unwrap().to_string(), a.clone())).collect()
}
fn strs(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

// ------------------------------------------------------------------ Modbus
#[test]
fn modbus_write_coil_classifies_and_records_operation() {
    let s = run(&[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[5, 0, 0x10, 0xFF, 0]))]);
    let a = by_label(&s);
    assert_eq!(a["10.0.0.10"]["device_type"], "PLC");
    assert!(strs(&a["10.0.0.10"]["roles"]).contains(&"Modbus server".into()));
    assert!(strs(&a["10.0.0.20"]["roles"]).contains(&"Modbus client".into()));
    let link = &s["links"][0];
    assert_eq!((link["source"].as_str(), link["target"].as_str()), (Some("10.0.0.20"), Some("10.0.0.10")));
    assert_eq!(link["operations"], json!({"Write Single Coil": 1}));
    assert_eq!(link["categories"], json!({"command": 1}));
}

#[test]
fn modbus_response_folds_into_client_server_link() {
    let s = run(&[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 2])),
                  tcp_rev("10.0.0.10", "10.0.0.20", 502, 50000, &mbap(1, &[3, 4, 0, 1, 0, 2]))]);
    assert_eq!(s["links"].as_array().unwrap().len(), 1);
    assert_eq!(s["links"][0]["packets"], 2);
}

#[test]
fn modbus_device_identification() {
    let mut pdu = vec![0x2B, 0x0E, 1, 1, 0, 0, 3];
    for (id, v) in [(0u8, &b"Schneider Electric"[..]), (1, b"BMX P34 2020"), (2, b"v3.10")] {
        pdu.push(id);
        pdu.push(v.len() as u8);
        pdu.extend(v);
    }
    let a = by_label(&run(&[tcp_rev("10.0.0.10", "10.0.0.20", 502, 50000, &mbap(1, &pdu))]));
    assert_eq!(a["10.0.0.10"]["vendor"], "Schneider Electric");
    assert_eq!(a["10.0.0.10"]["product_code"], "BMX P34 2020");
    assert_eq!(a["10.0.0.10"]["firmware"], "v3.10");
}

#[test]
fn umas_stop_is_critical_and_marks_workstation() {
    let s = run(&[tcp("10.0.0.30", "10.0.0.10", 50001, 502, &mbap(0, &[0x5A, 0, 0x41]))]);
    assert_eq!(s["alerts"][0]["severity"], "critical");
    assert!(s["alerts"][0]["title"].as_str().unwrap().contains("UMAS Stop PLC"));
    assert_eq!(by_label(&s)["10.0.0.30"]["device_type"], "Engineering workstation");
}

#[test]
fn modbus_force_listen_only_and_dedup() {
    let s = run(&[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[8, 0, 4, 0, 0]))]);
    assert_eq!(s["alerts"][0]["severity"], "high");
    let frame = tcp("10.0.0.30", "10.0.0.10", 50001, 502, &mbap(0, &[0x5A, 0, 0x41]));
    let s = run(&[frame.clone(), frame.clone(), frame]);
    assert_eq!(s["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(s["alerts"][0]["count"], 3);
}

// ---------------------------------------------------------------------- S7
#[test]
fn s7_plc_stop() {
    let s7 = s7_header(1, 1, b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM", &[]);
    let s = run(&[tcp("10.0.0.40", "10.0.0.11", 50100, 102, &tpkt_cotp(&s7))]);
    assert_eq!(s["alerts"][0]["title"], "S7 PLC Stop 명령");
    let plc = &by_label(&s)["10.0.0.11"];
    assert_eq!(plc["vendor"], "Siemens");
    assert_eq!(plc["device_type"], "PLC (Siemens S7)");
}

#[test]
fn s7_download_block_is_attributed_to_workstation() {
    let s7 = s7_header(1, 2, &[0x1B, 0], &[]);
    let s = run(&[tcp_rev("10.0.0.11", "10.0.0.40", 102, 50100, &tpkt_cotp(&s7))]);
    let alert = &s["alerts"][0];
    assert!(alert["title"].as_str().unwrap().contains("다운로드"));
    assert_eq!((alert["src"].as_str(), alert["dst"].as_str()), (Some("10.0.0.40"), Some("10.0.0.11")));
    assert_eq!(by_label(&s)["10.0.0.11"]["device_type"], "PLC (Siemens S7)");
    assert_ne!(by_label(&s)["10.0.0.40"]["device_type"], "PLC (Siemens S7)");
}

fn szl_response(model: &str, fw: (u8, u8, u8)) -> Vec<u8> {
    let params = [0, 1, 0x12, 8, 0x12, 0x84, 1, 1, 0, 0, 0, 0];
    let mut rec1 = vec![0, 1];
    rec1.extend(format!("{model:<20}").as_bytes());
    rec1.extend([0, 0xC0, 0, 4, 0, 1]);
    let mut rec2 = vec![0, 7];
    rec2.extend([b' '; 20]);
    rec2.extend([0, 0xC0, b'V', fw.0, fw.1, fw.2]);
    let mut data = vec![0xFF, 9, 0, 64, 0, 0x11, 0, 0, 0, 28, 0, 2];
    data.extend(rec1);
    data.extend(rec2);
    tcp_rev("10.0.0.11", "10.0.0.40", 102, 50100, &tpkt_cotp(&s7_header(7, 1, &params, &data)))
}

#[test]
fn s7_szl_module_identification() {
    let plc = &by_label(&run(&[szl_response("6ES7 315-2EH14-0AB0", (3, 2, 4))]))["10.0.0.11"];
    assert_eq!(plc["model"], "6ES7 315-2EH14-0AB0");
    assert_eq!(plc["firmware"], "V3.2.4");
}

#[test]
fn non_s7_iso_payload_is_mms() {
    let s = run(&[tcp("10.0.0.50", "10.0.0.12", 50200, 102, &tpkt_cotp(&[0x0D, 0x10]))]);
    assert_eq!(by_label(&s)["10.0.0.12"]["device_type"], "IED (IEC 61850)");
}

// ------------------------------------------------------------- EtherNet/IP
fn enip(command: u16, body: &[u8]) -> Vec<u8> {
    let mut v = command.to_le_bytes().to_vec();
    v.extend((body.len() as u16).to_le_bytes());
    v.extend([0u8; 20]);
    [v, body.to_vec()].concat()
}

#[test]
fn enip_list_identity() {
    let name = b"1756-L71/B LOGIX5571";
    let mut item = vec![1, 0, 0, 2, 0xAF, 0x12];
    item.extend(ip("10.0.0.13"));
    item.extend([0u8; 8]);
    item.extend([1, 0, 0x0E, 0, 55, 0, 20, 11, 0x60, 0]);
    item.extend(0x00C0FFEEu32.to_le_bytes());
    item.push(name.len() as u8);
    item.extend(name);
    item.push(3);
    let mut body = vec![1, 0, 0x0C, 0];
    body.extend((item.len() as u16).to_le_bytes());
    body.extend(item);
    let s = run(&[udp_full("10.0.0.13", "10.0.0.20", 44818, 50000, &enip(0x63, &body), PLC_MAC, HMI_MAC)]);
    let plc = &by_label(&s)["10.0.0.13"];
    assert_eq!(plc["vendor"], "Rockwell Automation/Allen-Bradley");
    assert_eq!(plc["model"], "1756-L71/B LOGIX5571");
    assert_eq!(plc["firmware"], "20.011");
    assert_eq!(plc["serial"], "0x00C0FFEE");
    assert_eq!(plc["device_type"], "PLC");
}

fn send_rr(cip: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 6];
    body.extend([2, 0, 0, 0, 0, 0, 0xB2, 0]);
    body.extend((cip.len() as u16).to_le_bytes());
    body.extend(cip);
    enip(0x6F, &body)
}

#[test]
fn cip_reset_and_logix_write_tag() {
    let s = run(&[tcp("10.0.0.20", "10.0.0.13", 50000, 44818, &send_rr(&[5, 2, 0x20, 1, 0x24, 1, 0]))]);
    assert_eq!(s["alerts"][0]["severity"], "critical");
    assert!(s["alerts"][0]["title"].as_str().unwrap().contains("Reset"));
    let inner = b"\x4d\x03\x91\x04Pump\xc1\x00\x01\x00\x01";
    let mut cip = vec![0x52, 2, 0x20, 6, 0x24, 1, 7, 0xE9];
    cip.extend((inner.len() as u16).to_le_bytes());
    cip.extend(inner);
    let s = run(&[tcp("10.0.0.20", "10.0.0.13", 50000, 44818, &send_rr(&cip))]);
    assert!(s["links"][0]["operations"].get("CIP Write Tag").is_some());
}

// ------------------------------------------------------------------- power
#[test]
fn dnp3_cold_restart_and_iec104() {
    let frame = [&b"\x05\x64\x08\xc4\x0a\x00\x01\x00\x00\x00"[..], b"\xc0\xc1\x0d", b"\x00\x00"].concat();
    let s = run(&[tcp("10.0.1.1", "10.0.1.50", 50000, 20000, &frame)]);
    assert_eq!(s["alerts"][0]["title"], "DNP3 Cold Restart 명령");
    assert_eq!(by_label(&s)["10.0.1.50"]["device_type"], "RTU/IED (DNP3 outstation)");

    let asdu = [0x2D, 1, 6, 0, 1, 0, 1, 0, 0, 0x81];
    let apdu = [&[0x68, (4 + asdu.len()) as u8, 0, 0, 0, 0][..], &asdu].concat();
    let s = run(&[tcp("10.0.1.1", "10.0.1.60", 50000, 2404, &apdu)]);
    assert!(s["alerts"][0]["title"].as_str().unwrap().contains("C_SC_NA_1"));

    let both = [0x68, 4, 7, 0, 0, 0, 0x68, 4, 0x43, 0, 0, 0];
    let s = run(&[tcp("10.0.1.1", "10.0.1.60", 50000, 2404, &both)]);
    assert_eq!(s["links"][0]["operations"], json!({"STARTDT act": 1, "TESTFR act": 1}));
}

// ----------------------------------------------------------------- layer 2
fn dcp_block(option: u8, sub: u8, value: &[u8], info: bool) -> Vec<u8> {
    let data = [if info { &[0u8, 0][..] } else { &[][..] }, value].concat();
    let mut b = vec![option, sub];
    b.extend((data.len() as u16).to_be_bytes());
    b.extend(&data);
    if data.len() % 2 == 1 {
        b.push(0);
    }
    b
}
fn dcp(frame_id: u16, service: u8, kind: u8, blocks: &[u8]) -> Vec<u8> {
    let mut v = frame_id.to_be_bytes().to_vec();
    v.extend([service, kind, 0, 0, 0, 1, 0, 0]);
    v.extend((blocks.len() as u16).to_be_bytes());
    [v, blocks.to_vec()].concat()
}

#[test]
fn dcp_identify_then_ip_traffic_merge() {
    let blocks = [dcp_block(2, 2, b"plc-line1", true), dcp_block(2, 1, b"S7-1500", true),
                  dcp_block(2, 3, &[0, 0x2A, 1, 0x0E], true),
                  dcp_block(1, 2, &[ip("10.0.2.10"), ip("255.255.255.0"), ip("10.0.2.1")].concat(), true)].concat();
    let l2 = ether(HMI_MAC, PLC_MAC, 0x8892, &dcp(0xFEFF, 5, 1, &blocks));
    let later = tcp_full("10.0.2.10", "10.0.2.99", 102, 50000, b"", PLC_MAC, HMI_MAC, 0x18);
    let s = run(&[l2, later]);
    let plc = &by_label(&s)["10.0.2.10"];
    assert_eq!(plc["name"], "plc-line1");
    assert_eq!(plc["model"], "S7-1500");
    assert_eq!(plc["vendor"], "Siemens");
    assert_eq!(plc["device_type"], "PLC (PROFINET)");
    assert!(strs(&plc["macs"]).contains(&PLC_MAC.into()));
    assert!(!s["assets"].as_array().unwrap().iter().any(|a| a["id"].as_str().unwrap().starts_with("mac:")));
}

#[test]
fn dcp_factory_reset_and_goose() {
    let s = run(&[ether(PLC_MAC, HMI_MAC, 0x8892, &dcp(0xFEFD, 4, 0, &dcp_block(5, 6, &[0, 0], false)))]);
    assert_eq!(s["alerts"][0]["severity"], "critical");

    let reference = b"IED1LD0/LLN0$GO$gcb1";
    let mut pdu = vec![0x80, reference.len() as u8];
    pdu.extend(reference);
    pdu.extend([0x85, 1, 5, 0x86, 1, 0]);
    let mut goose = vec![0, 1];
    goose.extend(((8 + 2 + pdu.len()) as u16).to_be_bytes());
    goose.extend([0, 0, 0, 0, 0x61, pdu.len() as u8]);
    goose.extend(pdu);
    let s = run(&[ether("01:0c:cd:01:00:01", PLC_MAC, 0x88B8, &goose)]);
    assert_eq!(s["assets"][0]["device_type"], "IED (IEC 61850)");
    assert_eq!(s["assets"][0]["name"], "IED1LD0");
    assert_eq!(s["links"], json!([]));
}

#[test]
fn slmp_remote_stop_on_custom_port() {
    let tail = [0x10, 0, 0x02, 0x10, 0, 0, 1, 0];
    let mut frame = vec![0x50, 0, 0, 0xFF, 0xFF, 3, 0];
    frame.extend((tail.len() as u16).to_le_bytes());
    frame.extend(tail);
    let s = run(&[tcp("10.0.3.5", "10.0.3.10", 50000, 5007, &frame)]);
    assert_eq!(s["alerts"][0]["title"], "MELSEC PLC Remote STOP 명령");
    assert_eq!(by_label(&s)["10.0.3.10"]["vendor"], "Mitsubishi Electric");
}

// ------------------------------------------------------------------ engine
#[test]
fn arp_records_sender_only_and_broadcast_creates_no_asset() {
    let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
    arp.extend(mac(HMI_MAC));
    arp.extend(ip("10.0.0.20"));
    arp.extend([0u8; 6]);
    arp.extend(ip("10.0.0.10"));
    let s = run(&[ether("ff:ff:ff:ff:ff:ff", HMI_MAC, 0x0806, &arp)]);
    assert_eq!(by_label(&s).keys().cloned().collect::<Vec<_>>(), vec!["10.0.0.20".to_string()]);
    let mut body = vec![0x63, 0];
    body.extend([0u8; 22]);
    let s = run(&[udp_full("10.0.0.20", "255.255.255.255", 44818, 44818, &body, HMI_MAC, "ff:ff:ff:ff:ff:ff")]);
    assert_eq!(by_label(&s).keys().cloned().collect::<Vec<_>>(), vec!["10.0.0.20".to_string()]);
}

#[test]
fn router_mac_is_not_attributed_to_remote_hosts() {
    let router = "00:00:5e:00:01:01";
    let s = run(&[udp_full("172.16.0.1", "10.0.0.10", 40000, 40001, b"x", router, PLC_MAC),
                  udp_full("172.16.0.2", "10.0.0.10", 40000, 40001, b"x", router, PLC_MAC)]);
    let a = by_label(&s);
    assert!(!strs(&a["172.16.0.1"]["macs"]).contains(&router.into()));
    assert!(!strs(&a["172.16.0.2"]["macs"]).contains(&router.into()));
}

#[test]
fn truncated_payload_and_port_hint_rules() {
    let s = run(&[tcp("10.0.0.20", "10.0.0.10", 50000, 102, &[3, 0, 0, 0x20, 2, 0xF0, 0x80, 0x32, 1])]);
    assert_eq!(s["stats"]["asset_count"], 2);
    let s = run(&[tcp_full("10.0.0.20", "10.0.0.10", 50000, 502, b"", HMI_MAC, PLC_MAC, 0x02),
                  tcp_full("10.0.0.10", "10.0.0.20", 502, 50000, b"", PLC_MAC, HMI_MAC, 0x12),
                  tcp_full("10.0.0.10", "10.0.0.20", 50001, 102, b"", PLC_MAC, HMI_MAC, 0x02),
                  tcp_full("10.0.0.20", "10.0.0.10", 102, 50001, b"", HMI_MAC, PLC_MAC, 0x14)]);
    let a = by_label(&s);
    assert_eq!(a["10.0.0.10"]["device_type"], "PLC candidate");
    assert_eq!(a["10.0.0.20"]["device_type"], "Unknown");
}

#[test]
fn persistence_round_trip_and_ack_reopen() {
    let mut store = Store::open_in_memory().unwrap();
    let mut engine = Engine::new();
    let stop = tcp("10.0.0.30", "10.0.0.10", 50001, 502, &mbap(0, &[0x5A, 0, 0x41]));
    feed(&mut engine, std::slice::from_ref(&stop), T0);
    store.save(&engine.take_changes()).unwrap();
    let mut restored = Engine::new();
    store.load_into(&mut restored).unwrap();
    let s = snap(&mut restored);
    assert_eq!(s["stats"]["asset_count"], 2);
    assert_eq!(s["alerts"][0]["count"], 1);
    assert_eq!(s["links"][0]["operations"], json!({"UMAS Stop PLC": 1}));

    let id = s["alerts"][0]["id"].as_u64().unwrap();
    assert!(restored.acknowledge(id));
    assert_eq!(snap(&mut restored)["stats"]["alert_open"], 0);
    feed(&mut restored, &[stop], T0 + 100_000);
    assert_eq!(snap(&mut restored)["stats"]["alert_open"], 1);
}

// ---------------------------------------------------------------- baseline
fn learned() -> Engine {
    let mut e = Engine::new();
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 2]))], T0);
    e.set_mode(Mode::Detecting, None, false);
    e
}
fn baseline_alerts(e: &mut Engine) -> Vec<Value> {
    snap(e)["alerts"].as_array().unwrap().iter().filter(|a| a["source"] == "baseline").cloned().collect()
}
const WRITE_REG: [u8; 5] = [6, 0, 0x10, 0, 1];

#[test]
fn baseline_learning_counts_and_silence() {
    let mut e = Engine::new();
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 2])),
                   tcp("10.0.0.21", "10.0.0.10", 50000, 502, &mbap(1, &WRITE_REG))], T0);
    assert!(baseline_alerts(&mut e).is_empty());
    assert_eq!(snap(&mut e)["baseline"]["counts"], json!({"asset": 3, "link": 2, "op": 2}));
    let mut e = learned();
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 2]))], T0 + 10_000);
    assert!(baseline_alerts(&mut e).is_empty());
}

#[test]
fn baseline_new_operation_new_asset_and_link() {
    let mut e = learned();
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &WRITE_REG))], T0 + 10_000);
    let alerts = baseline_alerts(&mut e);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0]["title"], "새로운 명령: Modbus/TCP Write Single Register");
    assert_eq!(alerts[0]["severity"], "medium");
    assert_eq!(alerts[0]["baseline"]["kind"], "op");

    let mut e = learned();
    feed(&mut e, &[tcp_rev("10.0.0.10", "10.0.0.20", 502, 50000, &mbap(1, &WRITE_REG))], T0 + 10_000);
    assert!(baseline_alerts(&mut e).is_empty(), "responses must not raise operation alerts");

    let mut e = learned();
    feed(&mut e, &[tcp_full("10.0.0.66", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 2]),
                            "00:0c:29:00:00:66", PLC_MAC, 0x18)], T0 + 10_000);
    let titles: HashMap<String, Value> = baseline_alerts(&mut e).into_iter()
        .map(|a| (a["title"].as_str().unwrap().to_string(), a)).collect();
    assert!(titles.contains_key("신규 자산 발견"));
    assert_eq!(titles["새로운 통신: Modbus/TCP"]["severity"], "high");
    assert_eq!(titles.len(), 2);
}

#[test]
fn baseline_policy_suppression_learning_and_reset() {
    let mut e = learned();
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(0, &[0x5A, 0, 0x41]))], T0 + 10_000);
    let sources: Vec<Value> = snap(&mut e)["alerts"].as_array().unwrap().iter().map(|a| a["source"].clone()).collect();
    assert_eq!(sources, vec![json!("policy")]);

    let mut e = learned();
    let frame = tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &WRITE_REG));
    feed(&mut e, std::slice::from_ref(&frame), T0 + 10_000);
    let id = baseline_alerts(&mut e)[0]["id"].as_u64().unwrap();
    assert!(e.learn_alert(id));
    feed(&mut e, &[frame], T0 + 20_000);
    let a = &baseline_alerts(&mut e)[0];
    assert_eq!((a["status"].as_str(), a["count"].as_u64()), (Some("acknowledged"), Some(1)));

    let mut e = learned();
    let new_link = tcp_full("10.0.0.20", "10.0.0.11", 50000, 502, &mbap(1, &WRITE_REG), HMI_MAC, "00:1b:1b:00:00:11", 0x18);
    feed(&mut e, std::slice::from_ref(&new_link), T0 + 10_000);
    let id = baseline_alerts(&mut e).iter().find(|a| a["baseline"]["kind"] == "link").unwrap()["id"].as_u64().unwrap();
    e.learn_alert(id);
    feed(&mut e, &[new_link], T0 + 20_000);
    assert!(!baseline_alerts(&mut e).iter().any(|a| a["baseline"]["kind"] == "op"));

    let mut e = learned();
    e.set_mode(Mode::Learning, None, true);
    assert_eq!(snap(&mut e)["baseline"]["counts"], json!({"asset": 0, "link": 0, "op": 0}));
    e.set_mode(Mode::Detecting, None, false);
    assert_eq!(snap(&mut e)["baseline"]["counts"]["link"], 1);
}

#[test]
fn baseline_window_expiry_and_persistence() {
    let mut e = Engine::new();
    e.set_mode(Mode::Learning, Some(1.0), false);
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 2]))], T0);
    e.baseline.learning_until = Some(crate::baseline::unix_now() - 1.0);
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &WRITE_REG))], T0 + 10_000);
    assert_eq!(snap(&mut e)["baseline"]["mode"], "detecting");
    assert_eq!(baseline_alerts(&mut e).len(), 1);

    let mut store = Store::open_in_memory().unwrap();
    let mut e = learned();
    store.save(&e.take_changes()).unwrap();
    let mut restored = Engine::new();
    store.load_into(&mut restored).unwrap();
    assert_eq!(snap(&mut restored)["baseline"]["mode"], "detecting");
    feed(&mut restored, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 2])),
                          tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &WRITE_REG))], T0 + 10_000);
    assert_eq!(baseline_alerts(&mut restored).len(), 1);
}

// ----------------------------------------------------------------- vulns
fn test_db() -> Arc<VulnDb> {
    let product = |vendor: &str, name: &str, versions: &str, cve: &str, cvss: f64, models: &[&str]| json!({
        "vendor": vendor, "product": name, "versions": versions, "models": models, "cves": [cve], "cvss": cvss});
    let adv = |id: &str, p: Value, cve: &str, kev: bool| json!({
        "id": id, "title": id, "published": "2024-01-02", "url": "", "cves": [cve], "products": [p],
        "kev_cves": if kev { vec![cve] } else { vec![] }});
    let db = json!({"format": "neteye-vulndb/1", "advisories": [
        adv("ICSA-T-01", product("Siemens", "SIMATIC ET 200S IM151-8 PN/DP CPU (6ES7151-8AB01-0AB0)", "vers:all/<V3.2.16",
                                 "CVE-2000-0001", 7.5, &["6ES7151-8AB01-0AB0"]), "CVE-2000-0001", false),
        adv("ICSA-T-02", product("Siemens", "SIMATIC S7-300 CPU family", "vers:all/*", "CVE-2000-0002", 9.8, &[]),
            "CVE-2000-0002", true),
        adv("ICSA-T-03", product("Siemens", "SIMATIC ET 200SP Open Controller CPU", "vers:all/*", "CVE-2000-0003", 9.6, &[]),
            "CVE-2000-0003", false),
    ]});
    Arc::new(VulnDb::from_json(db.to_string().as_bytes()).unwrap())
}

#[test]
fn vulnerability_matching_from_traffic() {
    let mut e = Engine::new();
    e.set_vulndb(Some(test_db()));
    feed(&mut e, &[szl_response("6ES7 151-8AB01-0AB0", (3, 2, 6))], T0);
    let s = snap(&mut e);
    let plc = &by_label(&s)["10.0.0.11"];
    let mut ids: Vec<&str> = plc["vulns"].as_array().unwrap().iter().map(|v| v["id"].as_str().unwrap()).collect();
    ids.sort();
    assert_eq!(ids, vec!["ICSA-T-01", "ICSA-T-02"]); // ET 200SP must not match ET 200S
    assert_eq!(plc["risk_level"], "critical");
    assert_eq!(s["stats"]["kev_assets"], 1);
    assert_eq!(s["alerts"][0]["title"], "악용 중인 취약점(KEV) 보유 자산");

    feed(&mut e, &[szl_response("6ES7 151-8AB01-0AB0", (3, 2, 17))], T0 + 100_000);
    let s = snap(&mut e);
    let ids: Vec<String> = by_label(&s)["10.0.0.11"]["vulns"].as_array().unwrap().iter()
        .map(|v| v["id"].as_str().unwrap().to_string()).collect();
    assert!(!ids.contains(&"ICSA-T-01".to_string()), "upgrade to V3.2.17 fixes ICSA-T-01");

    let mut late = Engine::new();
    feed(&mut late, &[szl_response("6ES7 151-8AB01-0AB0", (3, 2, 6))], T0);
    assert_eq!(snap(&mut late)["stats"]["vulnerable_assets"], 0);
    late.set_vulndb(Some(test_db()));
    assert_eq!(snap(&mut late)["stats"]["vulnerable_assets"], 1);
}

// ------------------------------------------------------- statistical profile
/// HMI polls PLC A and PLC B once a second for ten minutes (learning), then detection starts.
fn polled_engine() -> (Engine, i64) {
    let mut e = Engine::new();
    let read = mbap(1, &[3, 0, 0, 0, 2]);
    let a = tcp("10.0.5.20", "10.0.5.10", 50000, 502, &read);
    let b = tcp_full("10.0.5.20", "10.0.5.11", 50001, 502, &read, HMI_MAC, "00:1b:1b:00:00:11", 0x18);
    let mut t = T0;
    for _ in 0..600 {
        e.process_raw(&a, t);
        e.process_raw(&b, t + 500);
        t += 1000;
    }
    e.set_mode(Mode::Detecting, None, false);
    (e, t)
}

fn anomaly_alerts(e: &mut Engine) -> Vec<Value> {
    snap(e)["alerts"].as_array().unwrap().iter().filter(|a| a["source"] == "anomaly").cloned().collect()
}

#[test]
fn polling_stop_raises_silence_alert_once() {
    let (mut e, mut t) = polled_engine();
    let read = mbap(1, &[3, 0, 0, 0, 2]);
    let b = tcp_full("10.0.5.20", "10.0.5.11", 50001, 502, &read, HMI_MAC, "00:1b:1b:00:00:11", 0x18);
    // PLC A stops being polled; PLC B keeps the capture clock moving for two minutes.
    for _ in 0..120 {
        e.process_raw(&b, t);
        t += 1000;
    }
    let alerts = anomaly_alerts(&mut e);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0]["title"], "통신 중단: Modbus/TCP");
    assert_eq!(alerts[0]["severity"], "high");
    assert_eq!((alerts[0]["src"].as_str(), alerts[0]["dst"].as_str()), (Some("10.0.5.20"), Some("10.0.5.10")));
    assert_eq!(alerts[0]["count"], 1, "reported once per gap");
}

#[test]
fn steady_polling_after_learning_is_silent() {
    let (mut e, mut t) = polled_engine();
    let read = mbap(1, &[3, 0, 0, 0, 2]);
    let a = tcp("10.0.5.20", "10.0.5.10", 50000, 502, &read);
    let b = tcp_full("10.0.5.20", "10.0.5.11", 50001, 502, &read, HMI_MAC, "00:1b:1b:00:00:11", 0x18);
    for _ in 0..600 {
        e.process_raw(&a, t);
        e.process_raw(&b, t + 500);
        t += 1000;
    }
    assert!(anomaly_alerts(&mut e).is_empty());
}

#[test]
fn flood_raises_spike_and_interval_alerts_and_siem_signatures() {
    let (mut e, mut t) = polled_engine();
    e.emit_events = true;
    let a = tcp("10.0.5.20", "10.0.5.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 2]));
    for _ in 0..1200 {
        e.process_raw(&a, t); // 20 requests per second
        t += 50;
    }
    e.process_raw(&a, t + 60_000);
    let titles: Vec<String> = anomaly_alerts(&mut e).iter().map(|a| a["title"].as_str().unwrap().to_string()).collect();
    assert!(titles.contains(&"트래픽 급증: Modbus/TCP".to_string()), "{titles:?}");
    assert!(titles.contains(&"폴링 주기 변화: Modbus/TCP".to_string()), "{titles:?}");
    let signatures: Vec<String> = e.take_events().into_iter().map(|ev| ev.signature).collect();
    assert!(signatures.contains(&"NE-ANOMALY-VOLUME".to_string()), "{signatures:?}");
    assert!(signatures.contains(&"NE-ANOMALY-INTERVAL".to_string()));
}

#[test]
fn learned_profiles_survive_restart_and_reset_clears_them() {
    let (mut e, t) = polled_engine();
    let mut store = Store::open_in_memory().unwrap();
    store.save(&e.take_changes()).unwrap();
    let mut restored = Engine::new();
    store.load_into(&mut restored).unwrap();
    let link = &snap(&mut restored)["links"].as_array().unwrap().iter()
        .find(|l| l["target"] == "10.0.5.10").unwrap().clone();
    assert!((link["profile"]["interval"]["mean"].as_f64().unwrap() - 1000.0).abs() < 1.0, "{link}");

    // After restart the last request time is unknown, so silence needs fresh traffic first.
    let read = mbap(1, &[3, 0, 0, 0, 2]);
    let a = tcp("10.0.5.20", "10.0.5.10", 50000, 502, &read);
    let b = tcp_full("10.0.5.20", "10.0.5.11", 50001, 502, &read, HMI_MAC, "00:1b:1b:00:00:11", 0x18);
    restored.process_raw(&a, t);
    for i in 0..120 {
        restored.process_raw(&b, t + i * 1000);
    }
    assert_eq!(anomaly_alerts(&mut restored).len(), 1);

    e.set_mode(Mode::Learning, None, true);
    assert!(snap(&mut e)["links"].as_array().unwrap().iter().all(|l| l.get("profile").is_none()));
}

// ------------------------------------------------------------ process values
fn points_of(s: &Value, asset: &str) -> HashMap<String, Value> {
    by_label(s)[asset].get("points").and_then(|p| p.as_array()).map(|ps| ps.iter()
        .map(|p| (p["point"].as_str().unwrap().to_string(), p.clone())).collect()).unwrap_or_default()
}

#[allow(clippy::type_complexity)]
fn s7_write(items: &[(u8, u16, u16, u8, u32, u8, &[u8])]) -> Vec<u8> {
    // (param transport size, elements, db, area, bit address, data transport size, data)
    let mut params = vec![0x05, items.len() as u8];
    let mut data = Vec::new();
    for (i, (tsize, n, db, area, addr, dtsize, bytes)) in items.iter().enumerate() {
        params.extend([0x12, 0x0A, 0x10, *tsize]);
        params.extend(n.to_be_bytes());
        params.extend(db.to_be_bytes());
        params.push(*area);
        params.extend(&addr.to_be_bytes()[1..]);
        let len = if matches!(dtsize, 0x03..=0x05) { bytes.len() as u16 * 8 } else { bytes.len() as u16 };
        let len = if *dtsize == 0x03 { 1 } else { len };
        data.extend([0x00, *dtsize]);
        data.extend(len.to_be_bytes());
        data.extend(*bytes);
        if bytes.len() % 2 == 1 && i + 1 < items.len() {
            data.push(0);
        }
    }
    tcp("10.0.6.40", "10.0.6.11", 50100, 102, &tpkt_cotp(&s7_header(1, 9, &params, &data)))
}

#[test]
fn write_values_are_extracted_per_protocol() {
    let mut fc16 = vec![16, 0, 100, 0, 3, 6];
    fc16.extend([0x00, 0x0A, 0x00, 0x14, 0xFF, 0xFF]);
    let s7 = s7_write(&[(0x05, 1, 10, 0x84, 4 * 8, 0x04, &(-5i16).to_be_bytes()),
                        (0x08, 1, 1, 0x84, 8 * 8, 0x07, &21.5f32.to_be_bytes()),
                        (0x01, 1, 1, 0x84, 3, 0x03, &[1])]);
    let name = b"Pump_Speed";
    let mut cip = vec![0x4D, 6, 0x91, name.len() as u8];
    cip.extend(name);
    cip.extend([0xCA, 0x00, 0x01, 0x00]);
    cip.extend(1450.5f32.to_le_bytes());
    let mut asdu = vec![50, 1, 6, 0, 7, 0, 0xA1, 0x0F, 0];
    asdu.extend(3.25f32.to_le_bytes());
    asdu.push(0);
    let iec = [&[0x68, (4 + asdu.len()) as u8, 0, 0, 0, 0][..], &asdu].concat();
    let s = run(&[
        tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(1, &[6, 0, 16, 0x05, 0xDC])),
        tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(1, &fc16)),
        tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(1, &[5, 0, 7, 0xFF, 0x00])),
        s7,
        tcp("10.0.6.20", "10.0.6.13", 50000, 44818, &send_rr(&cip)),
        tcp("10.0.6.30", "10.0.6.60", 50000, 2404, &iec),
    ]);
    let modbus = points_of(&s, "10.0.6.10");
    assert_eq!(modbus["u1 HR16"]["last"], 1500.0);
    assert_eq!((modbus["u1 HR100"]["last"].as_f64(), modbus["u1 HR102"]["last"].as_f64()), (Some(10.0), Some(65535.0)));
    assert_eq!(modbus["u1 CO7"]["stateful"], true);
    let s7 = points_of(&s, "10.0.6.11");
    assert_eq!(s7["DB10.DBW4"]["last"], -5.0);
    assert_eq!(s7["DB1.DBD8"]["last"], 21.5);
    assert_eq!(s7["DB1.DBX0.3"]["last"], 1.0);
    assert_eq!(points_of(&s, "10.0.6.13")["Pump_Speed"]["last"], 1450.5);
    assert_eq!(points_of(&s, "10.0.6.60")["CA7 IOA4001 C_SE_NC"]["last"], 3.25);
}

fn setpoint(value: u16) -> Vec<u8> {
    let v = value.to_be_bytes();
    tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(1, &[6, 0, 16, v[0], v[1]]))
}

#[test]
fn setpoint_tampering_new_registers_and_coil_states_are_flagged() {
    let mut e = Engine::new();
    e.emit_events = true;
    let learn: Vec<Vec<u8>> = [1200u16, 1350, 1500, 1420, 1300].iter().map(|v| setpoint(*v)).collect();
    let coil_on = tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(1, &[5, 0, 7, 0xFF, 0x00]));
    feed(&mut e, &learn, T0);
    feed(&mut e, &[coil_on.clone(), coil_on.clone(), coil_on], T0 + 10_000);
    e.set_mode(Mode::Detecting, None, false);

    feed(&mut e, &[setpoint(1450)], T0 + 60_000);
    assert!(anomaly_alerts(&mut e).is_empty(), "inside the learned range");

    feed(&mut e, &[setpoint(3500),
                   tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(1, &[6, 0, 99, 0, 1])),
                   tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(1, &[5, 0, 7, 0x00, 0x00]))], T0 + 70_000);
    let alerts: HashMap<String, Value> = anomaly_alerts(&mut e).into_iter()
        .map(|a| (a["title"].as_str().unwrap().to_string(), a)).collect();
    let range = &alerts["공정 값 범위 이탈: u1 HR16"];
    assert_eq!(range["severity"], "high");
    assert_eq!((range["src"].as_str(), range["dst"].as_str()), (Some("10.0.6.20"), Some("10.0.6.10")));
    assert_eq!((range["details"]["value"].as_i64(), range["details"]["learned_max"].as_i64()), (Some(3500), Some(1500)));
    assert!(alerts.contains_key("학습되지 않은 주소에 쓰기: u1 HR99"));
    assert!(alerts.contains_key("학습되지 않은 상태 값: u1 CO7"));
    let signatures: Vec<String> = e.take_events().into_iter().map(|ev| ev.signature).collect();
    for sig in ["NE-PROCESS-RANGE", "NE-PROCESS-NEWPOINT", "NE-PROCESS-STATE"] {
        assert!(signatures.contains(&sig.to_string()), "{sig} in {signatures:?}");
    }
}

#[test]
fn learned_points_persist_and_reset_clears_them() {
    let mut e = Engine::new();
    feed(&mut e, &[1200u16, 1350, 1500].iter().map(|v| setpoint(*v)).collect::<Vec<_>>(), T0);
    e.set_mode(Mode::Detecting, None, false);
    let mut store = Store::open_in_memory().unwrap();
    store.save(&e.take_changes()).unwrap();
    let mut restored = Engine::new();
    store.load_into(&mut restored).unwrap();
    feed(&mut restored, &[setpoint(9000)], T0 + 60_000);
    assert_eq!(anomaly_alerts(&mut restored).len(), 1, "learned range survived the restart");

    restored.set_mode(Mode::Learning, None, true);
    assert!(points_of(&snap(&mut restored), "10.0.6.10").is_empty());
    store.save(&restored.take_changes()).unwrap();
    let mut again = Engine::new();
    store.load_into(&mut again).unwrap();
    assert!(again.points.is_empty(), "reset also cleared the stored points");
}

// ---------------------------------------------------------- measured values
fn mbap_tid(tid: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut v = tid.to_be_bytes().to_vec();
    v.extend([0, 0]);
    v.extend(((pdu.len() + 1) as u16).to_be_bytes());
    v.push(unit);
    v.extend(pdu);
    v
}

/// HMI polls HR100..HR101 (temperature, pressure); `temp` is what the PLC answers.
fn poll(tid: u16, temp: u16, pressure: u16) -> [Vec<u8>; 2] {
    let request = tcp("10.0.7.20", "10.0.7.10", 50000, 502, &mbap_tid(tid, 1, &[3, 0, 100, 0, 2]));
    let mut pdu = vec![3, 4];
    pdu.extend(temp.to_be_bytes());
    pdu.extend(pressure.to_be_bytes());
    let response = tcp_rev("10.0.7.10", "10.0.7.20", 502, 50000, &mbap_tid(tid, 1, &pdu));
    [request, response]
}

#[test]
fn modbus_read_responses_are_paired_and_judged() {
    let mut e = Engine::new();
    let mut t = T0;
    for i in 0..20u16 {
        feed(&mut e, &poll(i, 600 + i * 5, 1013), t); // 60.0 .. 69.5 degC (x10)
        t += 2000;
    }
    let points = points_of(&snap(&mut e), "10.0.7.10");
    assert_eq!(points["u1 HR100"]["kind"], "read");
    assert_eq!(points["u1 HR100"]["last"], 695.0);
    assert_eq!(points["u1 HR101"]["min"], 1013.0);

    e.set_mode(Mode::Detecting, None, false);
    feed(&mut e, &poll(100, 700, 1013), t); // slight drift: inside the 25 % margin
    assert!(anomaly_alerts(&mut e).is_empty());
    feed(&mut e, &poll(101, 950, 1013), t + 2000);
    let alerts = anomaly_alerts(&mut e);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0]["title"], "측정값 범위 이탈: u1 HR100");
    assert_eq!(alerts[0]["severity"], "medium");
    assert_eq!((alerts[0]["src"].as_str(), alerts[0]["dst"].as_str()), (Some("10.0.7.20"), Some("10.0.7.10")));

    // A response without its request (missed packet) is ignored rather than mis-addressed.
    let [_, orphan] = poll(999, 9999, 9999);
    feed(&mut e, &[orphan], t + 4000);
    assert_eq!(anomaly_alerts(&mut e).len(), 1);
}

#[test]
fn s7_read_var_and_iec104_measurements_are_decoded() {
    // Read Var job for DB10.DBD4 (REAL) and M10.2 (BIT), then the Ack_Data with the values.
    let item = |tsize: u8, db: u16, area: u8, addr: u32| {
        let mut v = vec![0x12, 0x0A, 0x10, tsize, 0, 1];
        v.extend(db.to_be_bytes());
        v.push(area);
        v.extend(&addr.to_be_bytes()[1..]);
        v
    };
    let params = [vec![0x04, 2], item(0x08, 10, 0x84, 4 * 8), item(0x01, 0, 0x83, 10 * 8 + 2)].concat();
    let job = tcp("10.0.7.40", "10.0.7.11", 50100, 102, &tpkt_cotp(&s7_header(1, 0x77, &params, &[])));
    let mut data = vec![0xFF, 0x07, 0, 4];
    data.extend(21.75f32.to_be_bytes());
    data.extend([0xFF, 0x03, 0, 1, 1]);
    let mut ack = vec![0x32, 3, 0, 0, 0, 0x77];
    ack.extend(2u16.to_be_bytes());
    ack.extend((data.len() as u16).to_be_bytes());
    ack.extend([0, 0, 0x04, 2]);
    ack.extend(&data);
    let ack = tcp_rev("10.0.7.11", "10.0.7.40", 102, 50100, &tpkt_cotp(&ack));

    // IEC 104: two float measurements in sequence (SQ=1) from IOA 3001, spontaneous.
    let mut asdu = vec![13, 0x82, 3, 0, 7, 0, 0xB9, 0x0B, 0];
    for v in [230.5f32, 231.0] {
        asdu.extend(v.to_le_bytes());
        asdu.push(0);
    }
    let iec = [&[0x68, (4 + asdu.len()) as u8, 0, 0, 0, 0][..], &asdu].concat();
    let s = run(&[job, ack, tcp_full("10.0.7.60", "10.0.7.30", 2404, 50000, &iec, PLC_MAC, HMI_MAC, 0x18)]);
    let s7 = points_of(&s, "10.0.7.11");
    assert_eq!(s7["DB10.DBD4"]["last"], 21.75);
    assert_eq!(s7["M10.2"]["last"], 1.0);
    let rtu = points_of(&s, "10.0.7.60");
    assert_eq!(rtu["CA7 IOA3001 M_ME_NC"]["last"], 230.5);
    assert_eq!(rtu["CA7 IOA3002 M_ME_NC"]["last"], 231.0);
    assert_eq!(rtu["CA7 IOA3002 M_ME_NC"]["kind"], "read");
}

// ------------------------------------------------------- CIP (Logix) reads
fn enip_ctx(command: u16, context: u64, body: &[u8]) -> Vec<u8> {
    let mut v = enip(command, body);
    v[12..20].copy_from_slice(&context.to_le_bytes());
    v
}
fn send_rr_ctx(context: u64, cip: &[u8]) -> Vec<u8> {
    let mut v = send_rr(cip);
    v[12..20].copy_from_slice(&context.to_le_bytes());
    v
}
fn send_unit(seq: u16, cip: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 6];
    body.extend([2, 0, 0xA1, 0, 4, 0, 0x01, 0x02, 0x03, 0x04, 0xB1, 0]);
    body.extend(((cip.len() + 2) as u16).to_le_bytes());
    body.extend(seq.to_le_bytes());
    body.extend(cip);
    enip_ctx(0x70, 0, &body)
}
fn tag_path(service: u8, tag: &str) -> Vec<u8> {
    let mut seg = vec![0x91, tag.len() as u8];
    seg.extend(tag.as_bytes());
    if tag.len() % 2 == 1 {
        seg.push(0);
    }
    [vec![service, (seg.len() / 2) as u8], seg].concat()
}
fn read_tag(tag: &str, count: u16) -> Vec<u8> {
    [tag_path(0x4C, tag), count.to_le_bytes().to_vec()].concat()
}
fn reply(service: u8, status: u8, data: &[u8]) -> Vec<u8> {
    [vec![service | 0x80, 0, status, 0], data.to_vec()].concat()
}
fn msp(services: &[Vec<u8>], reply_header: Option<u8>) -> Vec<u8> {
    let mut table = (services.len() as u16).to_le_bytes().to_vec();
    let mut off = 2 + services.len() * 2;
    for s in services {
        table.extend((off as u16).to_le_bytes());
        off += s.len();
    }
    let header = match reply_header {
        Some(status) => vec![0x8A, 0, status, 0],
        None => vec![0x0A, 2, 0x20, 0x02, 0x24, 0x01],
    };
    [header, table, services.concat()].concat()
}

#[test]
fn logix_read_tag_replies_are_paired_by_sender_context() {
    let mut e = Engine::new();
    e.emit_events = true;
    let mut t = T0;
    let level = |ctx: u64, v: f32| [
        tcp("10.0.8.20", "10.0.8.13", 50000, 44818, &send_rr_ctx(ctx, &read_tag("Tank_Level", 1))),
        tcp_rev("10.0.8.13", "10.0.8.20", 44818, 50000,
                &send_rr_ctx(ctx, &reply(0x4C, 0, &[&[0xCA, 0][..], &v.to_le_bytes()].concat()))),
    ];
    for i in 0..20u64 {
        feed(&mut e, &level(i, 50.0 + i as f32 * 0.5), t);
        t += 2000;
    }
    let points = points_of(&snap(&mut e), "10.0.8.13");
    assert_eq!(points["Tank_Level"]["kind"], "read");
    assert_eq!(points["Tank_Level"]["last"], 59.5);

    e.set_mode(Mode::Detecting, None, false);
    // Two outstanding requests answered out of order: each reply still lands on its own tag.
    let pressure = tcp("10.0.8.20", "10.0.8.13", 50000, 44818, &send_rr_ctx(500, &read_tag("Pressure", 1)));
    let [level_req, level_resp] = level(501, 250.0);
    let pressure_resp = tcp_rev("10.0.8.13", "10.0.8.20", 44818, 50000,
                                &send_rr_ctx(500, &reply(0x4C, 0, &[0xC4, 0, 7, 0, 0, 0])));
    feed(&mut e, &[pressure, level_req, level_resp, pressure_resp], t);
    let alerts = anomaly_alerts(&mut e);
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    assert_eq!(alerts[0]["title"], "측정값 범위 이탈: Tank_Level");
    assert_eq!(points_of(&snap(&mut e), "10.0.8.13")["Pressure"]["last"], 7.0);
    assert!(e.take_events().iter().any(|ev| ev.signature == "NE-MEASURE-RANGE"));

    // An error reply carries no value.
    feed(&mut e, &[tcp("10.0.8.20", "10.0.8.13", 50000, 44818, &send_rr_ctx(600, &read_tag("Valve", 1))),
                   tcp_rev("10.0.8.13", "10.0.8.20", 44818, 50000, &send_rr_ctx(600, &reply(0x4C, 0x05, &[])))], t + 10_000);
    assert!(!points_of(&snap(&mut e), "10.0.8.13").contains_key("Valve"));
}

#[test]
fn multiple_service_packet_over_connected_messaging() {
    // One packet reads a DINT, writes a REAL setpoint, and reads an INT[3]; the reply lists
    // three answers in the same order.
    let request = msp(&[read_tag("Temp", 1),
                        [tag_path(0x4D, "SP"), vec![0xCA, 0, 1, 0], 72.5f32.to_le_bytes().to_vec()].concat(),
                        read_tag("Arr", 3)], None);
    let response = msp(&[reply(0x4C, 0, &[0xC4, 0, 0x2A, 0, 0, 0]),
                         reply(0x4D, 0, &[]),
                         reply(0x4C, 0, &[0xC3, 0, 1, 0, 0xFE, 0xFF, 3, 0])], Some(0));
    // A second, unanswered packet with another sequence count must not steal the reply.
    let other = msp(&[read_tag("Other", 1)], None);
    let s = run(&[
        tcp("10.0.8.20", "10.0.8.13", 50000, 44818, &send_unit(7, &request)),
        tcp("10.0.8.20", "10.0.8.13", 50000, 44818, &send_unit(8, &other)),
        tcp_rev("10.0.8.13", "10.0.8.20", 44818, 50000, &send_unit(7, &response)),
    ]);
    let points = points_of(&s, "10.0.8.13");
    assert_eq!(points["Temp"]["last"], 42.0);
    assert_eq!(points["Temp"]["kind"], "read");
    assert_eq!(points["SP"]["last"], 72.5);
    assert_eq!(points["SP"]["kind"], "write");
    assert_eq!((points["Arr[0]"]["last"].as_f64(), points["Arr[1]"]["last"].as_f64(), points["Arr[2]"]["last"].as_f64()),
               (Some(1.0), Some(-2.0), Some(3.0)));
    assert!(!points.contains_key("Other"));

    // Partial failure (general status 0x1E): the failed read is skipped, the rest still count.
    let request = msp(&[read_tag("A", 1), read_tag("B", 1)], None);
    let response = msp(&[reply(0x4C, 0x04, &[]), reply(0x4C, 0, &[0xC1, 0, 1])], Some(0x1E));
    let s = run(&[
        tcp("10.0.8.20", "10.0.8.13", 50000, 44818, &send_unit(9, &request)),
        tcp_rev("10.0.8.13", "10.0.8.20", 44818, 50000, &send_unit(9, &response)),
    ]);
    let points = points_of(&s, "10.0.8.13");
    assert!(!points.contains_key("A"));
    assert_eq!(points["B"]["last"], 1.0);
    assert_eq!(points["B"]["stateful"], true);
}

#[test]
fn links_count_replies_separately_for_the_traffic_view() {
    let mut frames = Vec::new();
    for tid in 0..3u16 {
        frames.extend(poll(tid, 600, 1013));
    }
    frames.push(poll(9, 600, 1013)[0].clone()); // one unanswered request
    let s = run(&frames);
    let link = &s["links"][0];
    assert_eq!((link["source"].as_str(), link["target"].as_str()), (Some("10.0.7.20"), Some("10.0.7.10")));
    assert_eq!((link["packets"].as_u64(), link["packets_back"].as_u64()), (Some(7), Some(3)));
}

// ------------------------------------------------------------ host identity
fn dhcp_request(client_mac: &str, hostname: &str, vendor: &str, requested: &str) -> Vec<u8> {
    let mut p = vec![1, 1, 6, 0, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0];
    p.extend([0u8; 16]); // ciaddr, yiaddr, siaddr, giaddr
    p.extend(mac(client_mac));
    p.extend([0u8; 10 + 64 + 128]);
    p.extend([0x63, 0x82, 0x53, 0x63, 53, 1, 3]);
    p.extend([50, 4]);
    p.extend(ip(requested));
    p.extend([12, hostname.len() as u8]);
    p.extend(hostname.as_bytes());
    p.extend([60, vendor.len() as u8]);
    p.extend(vendor.as_bytes());
    p.push(255);
    udp_full("0.0.0.0", "255.255.255.255", 68, 67, &p, client_mac, "ff:ff:ff:ff:ff:ff")
}

#[test]
fn dhcp_names_the_client_once_it_appears_and_creates_nothing_itself() {
    let pc = "00:0c:29:aa:bb:cc";
    let mut e = Engine::new();
    feed(&mut e, &[dhcp_request(pc, "ENG-WS01", "MSFT 5.0", "10.0.9.50")], T0);
    assert!(by_label(&snap(&mut e)).is_empty(), "a requested address is not an asset");

    let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
    arp.extend(mac(pc));
    arp.extend(ip("10.0.9.50"));
    arp.extend([0u8; 6]);
    arp.extend(ip("10.0.9.1"));
    feed(&mut e, &[ether("ff:ff:ff:ff:ff:ff", pc, 0x0806, &arp)], T0 + 1000);
    let a = &by_label(&snap(&mut e))["10.0.9.50"];
    assert_eq!((a["hostname"].as_str(), a["os"].as_str()), (Some("ENG-WS01"), Some("Windows")));
    assert!(a["os_evidence"].as_str().unwrap().contains("MSFT 5.0"));

    // A later DHCP renewal from the same client reaches the asset directly.
    feed(&mut e, &[dhcp_request(pc, "ENG-WS01-NEW", "MSFT 5.0", "10.0.9.50")], T0 + 2000);
    assert_eq!(by_label(&snap(&mut e))["10.0.9.50"]["hostname"], "ENG-WS01-NEW");
}

#[test]
fn tcp_syn_fingerprint_names_internal_windows_hosts_only() {
    let syn = |src: &str| {
        let mut seg = vec![0xC3, 0x50, 0x01, 0xF6, 0, 0, 0, 1, 0, 0, 0, 0, 8 << 4, 0x02, 0xFA, 0xF0, 0, 0, 0, 0];
        seg.extend([2, 4, 5, 0xB4, 1, 3, 3, 8, 1, 1, 4, 2]); // M,N,W(8),N,N,S
        let mut ip_hdr = vec![0x45, 0, 0, (20 + seg.len()) as u8, 0, 1, 0x40, 0, 128, 6, 0, 0];
        ip_hdr.extend(ip(src));
        ip_hdr.extend(ip("10.0.0.10"));
        ether(PLC_MAC, HMI_MAC, 0x0800, &[ip_hdr, seg].concat())
    };
    let s = run(&[syn("10.0.0.20"), syn("8.8.4.4")]);
    let a = by_label(&s);
    assert_eq!(a["10.0.0.20"]["os"], "Windows 10/11 · Server 2016 이상");
    assert!(a["8.8.4.4"].get("os").is_none(), "internet hosts are not fingerprinted");
}

#[test]
fn operator_entered_details_override_and_drive_vulnerability_matching() {
    use crate::engine::ManualInfo;
    let mut e = Engine::new();
    e.set_vulndb(Some(test_db()));
    // An unidentified device: only Modbus traffic, no identity.
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 1]))], T0);
    assert!(by_label(&snap(&mut e))["10.0.0.10"]["vulns"].as_array().unwrap().is_empty());

    let info = ManualInfo {
        name: "보일러 #2 제어 PLC".into(), vendor: "Siemens".into(), model: "S7-300 CPU 315-2 PN/DP".into(),
        location: "B동 2층 보일러실".into(), owner: "설비팀 김OO".into(), criticality: "high".into(),
        notes: "정기 점검: 매월 첫째 주\n교체 예정 2027".into(), ..Default::default()
    };
    e.set_manual("10.0.0.10", info, "operator1", T0 + 1000).unwrap();
    let s = snap(&mut e);
    let plc = &by_label(&s)["10.0.0.10"];
    assert_eq!(plc["vendor"], "Siemens", "entered value shown");
    assert_eq!(plc["auto"]["vendor"], "", "automatic value kept alongside");
    assert_eq!(plc["manual"]["name"], "보일러 #2 제어 PLC");
    assert_eq!(plc["manual"]["updated_by"], "operator1");
    assert_eq!(plc["manual"]["notes"], "정기 점검: 매월 첫째 주\n교체 예정 2027");
    let ids: Vec<&str> = plc["vulns"].as_array().unwrap().iter().map(|v| v["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["ICSA-T-02"], "S7-300 entered by hand is matched");

    // Survives a restart; storage keeps automatic values separate from the entered ones.
    let mut store = Store::open_in_memory().unwrap();
    store.save(&e.take_changes()).unwrap();
    let mut restored = Engine::new();
    store.load_into(&mut restored).unwrap();
    let a = &by_label(&snap(&mut restored))["10.0.0.10"];
    assert_eq!((a["vendor"].as_str(), a["manual"]["location"].as_str()), (Some("Siemens"), Some("B동 2층 보일러실")));

    // Validation, unknown assets, and clearing.
    let bad = ManualInfo { criticality: "urgent".into(), ..Default::default() };
    assert!(e.set_manual("10.0.0.10", bad, "operator1", T0).is_err());
    assert!(e.set_manual("10.9.9.9", ManualInfo::default(), "operator1", T0).is_err());
    e.set_manual("10.0.0.10", ManualInfo::default(), "operator1", T0 + 2000).unwrap();
    let a = &by_label(&snap(&mut e))["10.0.0.10"];
    assert!(a.get("manual").is_none() && a["vendor"] == "" && a["vulns"].as_array().unwrap().is_empty());
}

// ------------------------------------------------------------ hostile input
#[test]
fn truncated_pcapng_option_is_rejected_without_panicking() {
    let mut f = Vec::new();
    // Section header block (28 bytes), little endian.
    f.extend([0x0A, 0x0D, 0x0D, 0x0A]);
    f.extend(28u32.to_le_bytes());
    f.extend([0x4D, 0x3C, 0x2B, 0x1A, 1, 0, 0, 0]);
    f.extend([0xFF; 8]);
    f.extend(28u32.to_le_bytes());
    // Interface block whose if_tsresol option (code 9, length 1) has no value byte.
    f.extend(1u32.to_le_bytes());
    f.extend(24u32.to_le_bytes());
    f.extend([1, 0, 0, 0, 0xFF, 0xFF, 0, 0]);
    f.extend([9, 0, 1, 0]);
    f.extend(24u32.to_le_bytes());
    let path = std::env::temp_dir().join(format!("neteye-trunc-{}.pcapng", std::process::id()));
    std::fs::write(&path, &f).unwrap();
    let result = std::panic::catch_unwind(|| crate::pcap::read_file(&path, |_, _| {}));
    let _ = std::fs::remove_file(&path);
    assert!(result.is_ok(), "malformed capture must not panic the importer");
}

#[test]
fn write_sweeps_over_unlearned_addresses_fold_into_one_alert() {
    let mut e = Engine::new();
    feed(&mut e, &[setpoint(1200), setpoint(1300), setpoint(1400)], T0);
    e.set_mode(Mode::Detecting, None, false);
    // An attacker writes to 60 registers it never touched before.
    let sweep: Vec<Vec<u8>> = (200..260u16).map(|reg| {
        let r = reg.to_be_bytes();
        tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(1, &[6, r[0], r[1], 0, 1]))
    }).collect();
    feed(&mut e, &sweep, T0 + 60_000);
    let alerts = anomaly_alerts(&mut e);
    let individual = alerts.iter().filter(|a| a["title"].as_str().unwrap().starts_with("학습되지 않은 주소에 쓰기: ")).count();
    let summary: Vec<&Value> = alerts.iter().filter(|a| a["title"] == "학습되지 않은 주소에 쓰기 (다수 주소)").collect();
    assert_eq!((individual, summary.len()), (20, 1));
    assert_eq!(summary[0]["count"], 40);
    assert_eq!(summary[0]["severity"], "high");
    // Every swept address stays visible in the summary.
    let listed = summary[0]["details"]["points"].as_array().unwrap();
    assert_eq!(listed.len(), 40);
    assert!(listed.contains(&json!("u1 HR259")));
}

#[test]
fn a_full_point_table_still_reports_writes_to_unknown_addresses() {
    let mut e = Engine::new();
    // Learn MAX_POINTS registers: two units x 50,000 holding registers, 16 per write.
    let mut frames = Vec::new();
    for unit in [1u8, 2] {
        for start in (0..50_000u16).step_by(16) {
            let mut pdu = vec![16];
            pdu.extend(start.to_be_bytes());
            pdu.extend(16u16.to_be_bytes());
            pdu.push(32);
            pdu.extend([0u8; 32]);
            frames.push(tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(unit, &pdu)));
        }
    }
    feed(&mut e, &frames, T0);
    assert_eq!(e.points.len(), crate::engine::MAX_POINTS);
    e.set_mode(Mode::Detecting, None, false);
    feed(&mut e, &[tcp("10.0.6.20", "10.0.6.10", 50000, 502, &mbap(3, &[6, 0, 7, 0, 1]))], T0 + 600_000_000);
    let alerts = anomaly_alerts(&mut e);
    let titles: Vec<&str> = alerts.iter().map(|a| a["title"].as_str().unwrap()).collect();
    assert!(titles.contains(&"공정 포인트 추적 한도 도달"), "{titles:?}");
    let sweep = alerts.iter().find(|a| a["title"] == "학습되지 않은 주소에 쓰기 (다수 주소)").expect("write still reported");
    assert_eq!(sweep["details"]["points"], json!(["u3 HR7"]));
    assert_eq!(e.points.len(), crate::engine::MAX_POINTS, "nothing more is stored");
}

// ------------------------------------------------------------ internet edge
fn dns_response(name: &str, addr: &str) -> Vec<u8> {
    let mut p = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend(label.as_bytes());
    }
    p.extend([0, 0, 1, 0, 1, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    p.extend(ip(addr));
    udp_full("10.0.0.1", "10.0.0.20", 53, 53000, &p, PLC_MAC, HMI_MAC)
}

fn client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut ext = vec![0, 0];
    ext.extend(((name.len() + 5) as u16).to_be_bytes());
    ext.extend(((name.len() + 3) as u16).to_be_bytes());
    ext.push(0);
    ext.extend((name.len() as u16).to_be_bytes());
    ext.extend(name);
    let mut hello = vec![3, 3];
    hello.extend([7u8; 32]);
    hello.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
    hello.extend((ext.len() as u16).to_be_bytes());
    hello.extend(ext);
    let mut hs = vec![1, 0];
    hs.extend((hello.len() as u16).to_be_bytes());
    hs.extend(hello);
    let mut rec = vec![0x16, 3, 1];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

fn externals(s: &Value) -> HashMap<String, Value> {
    s["external"].as_array().unwrap().iter().map(|x| (x["ip"].as_str().unwrap().to_string(), x.clone())).collect()
}

fn ext_titles(s: &Value) -> Vec<String> {
    s["alerts"].as_array().unwrap().iter().filter(|a| a["source"] == "external")
        .map(|a| a["title"].as_str().unwrap().to_string()).collect()
}

#[test]
fn internet_destinations_get_names_and_services() {
    let s = run(&[
        dns_response("update.example.com", "8.8.4.4"),
        tcp_full("10.0.0.20", "8.8.4.4", 51000, 443, &[], HMI_MAC, PLC_MAC, 0x02),
        tcp_full("8.8.4.4", "10.0.0.20", 443, 51000, &[], PLC_MAC, HMI_MAC, 0x12),
        tcp_full("10.0.0.20", "9.9.9.9", 51001, 443, &client_hello("api.example.net"), HMI_MAC, PLC_MAC, 0x18),
        tcp_full("10.0.0.20", "1.1.1.1", 51002, 7777, &[], HMI_MAC, PLC_MAC, 0x02),
    ]);
    let ext = externals(&s);
    assert_eq!(ext["8.8.4.4"]["domains"], json!(["update.example.com"]));
    assert_eq!(ext["8.8.4.4"]["services"][0]["name"], "HTTPS");
    assert_eq!(ext["8.8.4.4"]["peers"], json!(["10.0.0.20"]));
    assert_eq!(ext["9.9.9.9"]["domains"], json!(["api.example.net"]));
    assert_eq!(by_label(&s)["8.8.4.4"]["domains"], json!(["update.example.com"]));
    // A nameless destination on an unusual port is flagged, an ordinary HTTPS one is not.
    let odd = ext["1.1.1.1"]["reasons"].as_array().unwrap();
    assert!(odd.contains(&json!("비표준 포트 7777/TCP")) && odd.contains(&json!("DNS·SNI 이름 없이 직접 접속")));
    assert!(ext["8.8.4.4"]["reasons"].as_array().unwrap().is_empty());
    assert!(ext_titles(&s).is_empty(), "ordinary browsing raises no alert");
}

#[test]
fn risky_internet_conversations_raise_alerts() {
    let mut e = Engine::new();
    let path = std::env::temp_dir().join(format!("neteye-bl-test-{}.txt", std::process::id()));
    std::fs::write(&path, "5.6.7.8 # Feodo Tracker\n").unwrap();
    e.set_intel(None, Some(Arc::new(crate::intel::Blocklist::load(&path).unwrap())));
    let _ = std::fs::remove_file(&path);
    feed(&mut e, &[
        // A PLC (Modbus server) that also talks to the internet.
        tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 1])),
        tcp_full("10.0.0.10", "4.4.4.4", 50100, 443, &[], PLC_MAC, HMI_MAC, 0x02),
        // Modbus across the internet.
        tcp_full("10.0.0.20", "4.2.2.2", 50001, 502, &mbap(1, &[3, 0, 0, 0, 1]), HMI_MAC, PLC_MAC, 0x18),
        // Remote desktop opened from the internet and accepted.
        tcp_full("1.2.3.4", "10.0.0.30", 40000, 3389, &[], PLC_MAC, HMI_MAC, 0x02),
        tcp_full("10.0.0.30", "1.2.3.4", 3389, 40000, &[], HMI_MAC, PLC_MAC, 0x12),
        // A host on a threat list.
        tcp_full("10.0.0.20", "5.6.7.8", 50002, 443, &[], HMI_MAC, PLC_MAC, 0x02),
        // A voice call: UDP between temporary ports, started by the outside peer. Not inbound access.
        udp_full("3.3.3.3", "10.0.0.40", 41210, 49480, &[0u8; 40], PLC_MAC, HMI_MAC),
        udp_full("10.0.0.40", "3.3.3.3", 49480, 41210, &[0u8; 40], HMI_MAC, PLC_MAC),
        // Mid-stream TCP data from inside to an outside client port is not "accepting" anything.
        tcp_full("10.0.0.41", "3.3.3.4", 8080, 50500, &[1, 2, 3], HMI_MAC, PLC_MAC, 0x18),
    ], T0);
    e.emit_events = true;
    let s = snap(&mut e);
    let titles = ext_titles(&s);
    for t in ["OT 장비의 인터넷 통신", "산업 프로토콜의 인터넷 통신", "인터넷에서 내부 서비스로 접속", "위협 인텔리전스 목록 주소와 통신"] {
        assert!(titles.contains(&t.to_string()), "{t} in {titles:?}");
    }
    let alerts: HashMap<String, Value> = s["alerts"].as_array().unwrap().iter()
        .map(|a| (a["title"].as_str().unwrap().to_string(), a.clone())).collect();
    assert_eq!(alerts["인터넷에서 내부 서비스로 접속"]["severity"], "critical", "RDP from the internet");
    assert_eq!(alerts["인터넷에서 내부 서비스로 접속"]["src"], "1.2.3.4");
    assert_eq!(alerts["인터넷에서 내부 서비스로 접속"]["count"], 1, "only the accepted RDP session");
    assert_eq!(alerts["위협 인텔리전스 목록 주소와 통신"]["details"]["threat_list"], "Feodo Tracker");
    let ext = externals(&s);
    assert_eq!(ext["5.6.7.8"]["score"], 100);
    assert_eq!(s["external"][0]["ip"], "5.6.7.8", "most suspicious first");
}

#[test]
fn site_networks_numbered_from_public_space_stay_internal() {
    let mut e = Engine::new();
    e.set_internal_nets(&["166.161.0.0/16".to_string()]).unwrap();
    feed(&mut e, &[tcp("166.161.16.20", "166.161.16.230", 50000, 502, &mbap(1, &[3, 0, 0, 0, 1]))], T0);
    let s = snap(&mut e);
    assert!(s["external"].as_array().unwrap().is_empty());
    assert!(ext_titles(&s).is_empty());
}

#[test]
fn ephemeral_source_ports_are_not_fieldbus_signatures() {
    let s = run(&[
        // A PC whose random source port happens to be 61450 (DNS) / 61451 (QUIC).
        udp_full("10.0.0.20", "8.8.8.8", 61450, 53, &[0u8; 30], HMI_MAC, PLC_MAC),
        udp_full("10.0.0.20", "142.250.1.1", 61451, 443, &[0u8; 30], HMI_MAC, PLC_MAC),
        // A real CC-Link IE Field Basic exchange between two stations.
        udp_full("10.0.1.5", "10.0.1.6", 61450, 61450, &[0u8; 30], "00:1b:1b:00:00:05", "00:1b:1b:00:00:06"),
    ]);
    let a = by_label(&s);
    assert_eq!(a["10.0.0.20"]["device_type"], "Unknown");
    assert!(!strs(&a["10.0.0.20"]["protocols"]).contains(&"CC-Link IE Field Basic".to_string()));
    assert_eq!(a["10.0.1.6"]["device_type"], "CC-Link IE Field Basic station");
}

#[test]
fn hosts_misread_by_earlier_versions_are_reset_on_load() {
    let mut e = Engine::new();
    let asset = |id: &str, kind: &str| json!({"id": id, "ip": id, "device_type": kind, "confidence": 0.7,
        "protocols": ["CC-Link IE Field Basic", "UDP"], "first_seen": "2026-11-17T00:00:00.000+00:00",
        "last_seen": "2026-11-17T00:00:00.000+00:00"});
    let link = |a: &str, b: &str| json!({"source": a, "target": b, "protocol": "UDP", "packets": 1});
    e.restore(vec![asset("10.0.0.20", "CC-Link IE Field Basic station"), asset("10.0.1.6", "CC-Link IE Field Basic station"),
                   asset("8.8.8.8", "Unknown")],
              vec![link("10.0.0.20", "8.8.8.8"), link("10.0.1.5", "10.0.1.6")], Vec::new(), None, Vec::new());
    assert_eq!(by_label(&snap(&mut e))["10.0.0.20"]["device_type"], "CC-Link IE Field Basic station",
               "loading alone changes nothing");
    e.run_migrations();
    let a = by_label(&snap(&mut e));
    assert_eq!(a["10.0.0.20"]["device_type"], "Unknown", "the PC that browses the internet is corrected");
    assert_eq!(a["10.0.1.6"]["device_type"], "CC-Link IE Field Basic station", "a real station is left alone");
}

#[test]
fn inbound_sprays_from_many_addresses_fold_into_a_summary() {
    let mut frames = Vec::new();
    for i in 1..=30u8 {
        let peer = format!("2.2.2.{i}");
        frames.push(tcp_full(&peer, "10.0.0.30", 40000, 3389, &[], PLC_MAC, HMI_MAC, 0x02));
        frames.push(tcp_full("10.0.0.30", &peer, 3389, 40000, &[], HMI_MAC, PLC_MAC, 0x12));
    }
    let s = run(&frames);
    let alerts: Vec<&Value> = s["alerts"].as_array().unwrap().iter().filter(|a| a["source"] == "external").collect();
    let individual = alerts.iter().filter(|a| a["title"] == "인터넷에서 내부 서비스로 접속").count();
    let summary: Vec<&&Value> = alerts.iter().filter(|a| a["title"] == "인터넷에서 내부 서비스로 접속 (다수 주소)").collect();
    assert_eq!((individual, summary.len()), (20, 1));
    assert_eq!(summary[0]["count"], 10);
    assert_eq!(summary[0]["details"]["peers"].as_array().unwrap().len(), 10);
}

#[test]
fn each_new_summary_peer_reaches_the_siem_with_its_address() {
    let mut e = Engine::new();
    e.emit_events = true;
    let mut frames = Vec::new();
    for i in 1..=25u8 {
        let peer = format!("2.2.3.{i}");
        frames.push(tcp_full(&peer, "10.0.0.30", 40000, 3389, &[], PLC_MAC, HMI_MAC, 0x02));
        frames.push(tcp_full("10.0.0.30", &peer, 3389, 40000, &[], HMI_MAC, PLC_MAC, 0x12));
    }
    feed(&mut e, &frames, T0);
    let peers: Vec<String> = e.take_events().iter().filter(|ev| ev.name.ends_with("(다수 주소)"))
        .filter_map(|ev| ev.details["peer"].as_str().map(str::to_string)).collect();
    assert_eq!(peers.len(), 5, "{peers:?}");
    assert!(peers.contains(&"2.2.3.25".to_string()));
}

#[test]
fn a_full_alert_table_evicts_old_noise_and_folds_the_rest() {
    let mut e = Engine::new();
    e.emit_events = true;
    feed(&mut e, &[tcp("10.0.0.20", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 1]))], T0);
    e.set_mode(Mode::Detecting, None, false);
    // Hundreds of new hosts, each a baseline alert (new asset / new conversation).
    let frames: Vec<Vec<u8>> = (0..400u32).map(|i| {
        tcp(&format!("10.1.{}.{}", i / 250, i % 250 + 1), "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 1]))
    }).collect();
    feed(&mut e, &frames, T0 + 10_000);
    let s = snap(&mut e);
    let alerts = s["alerts"].as_array().unwrap();
    // New-host alerts are high severity: they are admitted up to twice the limit, then folded.
    assert!(s["stats"]["alert_open"].as_u64().unwrap() <= 601, "bounded: {}", s["stats"]["alert_open"]);
    let overflow = alerts.iter().find(|a| a["title"].as_str().unwrap().starts_with("경고 수 한도 도달")).expect("summary");
    assert_eq!(overflow["details"]["recent"].as_array().unwrap().len(), 50, "most recent kept");
    assert!(overflow["count"].as_u64().unwrap() > 50);
    // Every folded alert is forwarded on its own, carrying what was folded.
    let events = e.take_events();
    let folded: Vec<_> = events.iter().filter(|ev| ev.name.starts_with("경고 수 한도")).collect();
    assert!(folded.len() as u64 >= overflow["count"].as_u64().unwrap() - 1, "{} folded events", folded.len());
    assert!(folded.iter().skip(1).all(|ev| ev.details["src"].as_str().is_some_and(|s| s.starts_with("10.1."))));

    // Acknowledged alerts make room again for new ones.
    let ids: Vec<u64> = alerts.iter().filter(|a| !a["title"].as_str().unwrap().starts_with("경고 수"))
        .take(100).map(|a| a["id"].as_u64().unwrap()).collect();
    for id in ids {
        e.acknowledge(id);
    }
    let _ = e.take_changes(); // the store has them now, so they may leave memory
    feed(&mut e, &[tcp("10.2.0.1", "10.0.0.10", 50000, 502, &mbap(1, &[3, 0, 0, 0, 1]))], T0 + 20_000);
    let s = snap(&mut e);
    assert!(s["alerts"].as_array().unwrap().iter().any(|a| a["src"] == "10.2.0.1"), "admitted after eviction");
}

#[test]
fn threat_list_matches_are_never_folded() {
    let mut e = Engine::new();
    let path = std::env::temp_dir().join(format!("neteye-bl-many-{}.txt", std::process::id()));
    std::fs::write(&path, "5.6.7.0/24 # Feodo Tracker\n").unwrap();
    e.set_intel(None, Some(Arc::new(crate::intel::Blocklist::load(&path).unwrap())));
    let _ = std::fs::remove_file(&path);
    let frames: Vec<Vec<u8>> = (1..=40u8).map(|i| {
        tcp_full("10.0.0.20", &format!("5.6.7.{i}"), 50000 + i as u16, 443, &[], HMI_MAC, PLC_MAC, 0x02)
    }).collect();
    feed(&mut e, &frames, T0);
    let s = snap(&mut e);
    let threat = s["alerts"].as_array().unwrap().iter().filter(|a| a["title"] == "위협 인텔리전스 목록 주소와 통신").count();
    assert_eq!(threat, 40);
}
