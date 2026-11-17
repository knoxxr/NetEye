import struct
import unittest

from backend.engine import Engine
from backend.storage import Store

PLC_MAC = "00:1b:1b:00:00:10"
HMI_MAC = "00:0c:29:00:00:20"


def mac(raw: str) -> bytes:
    return bytes.fromhex(raw.replace(":", ""))


def ip(raw: str) -> bytes:
    return bytes(int(p) for p in raw.split("."))


def ether(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return mac(dst) + mac(src) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, l4: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, ip(src), ip(dst))
    return header + l4


def tcp(src: str, dst: str, sport: int, dport: int, payload: bytes,
        src_mac: str = HMI_MAC, dst_mac: str = PLC_MAC, flags: int = 0x18) -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 8192, 0, 0) + payload
    return ether(dst_mac, src_mac, 0x0800, ipv4(src, dst, 6, seg))


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes,
        src_mac: str = HMI_MAC, dst_mac: str = PLC_MAC) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ether(dst_mac, src_mac, 0x0800, ipv4(src, dst, 17, seg))


def mbap(unit: int, pdu: bytes, tid: int = 1) -> bytes:
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def tpkt_cotp(s7: bytes) -> bytes:
    body = b"\x02\xf0\x80" + s7
    return struct.pack("!BBH", 3, 0, 4 + len(body)) + body


def run(*frames: bytes) -> dict:
    engine = Engine()
    for i, frame in enumerate(frames):
        engine.process_raw(frame, 1_700_000_000 + i)
    return engine.snapshot()


def by_label(snapshot: dict) -> dict:
    return {a["label"]: a for a in snapshot["assets"]}


class ModbusTests(unittest.TestCase):
    def test_write_coil_classifies_and_records_operation(self):
        snap = run(tcp("10.0.0.20", "10.0.0.10", 50000, 502,
                       mbap(1, b"\x05\x00\x10\xff\x00")))
        assets = by_label(snap)
        self.assertEqual(assets["10.0.0.10"]["device_type"], "PLC")
        self.assertIn("Modbus server", assets["10.0.0.10"]["roles"])
        self.assertIn("Modbus client", assets["10.0.0.20"]["roles"])
        link = snap["links"][0]
        self.assertEqual((link["source"], link["target"]), ("10.0.0.20", "10.0.0.10"))
        self.assertEqual(link["operations"], {"Write Single Coil": 1})
        self.assertEqual(link["categories"], {"command": 1})

    def test_response_is_folded_into_client_to_server_link(self):
        snap = run(tcp("10.0.0.20", "10.0.0.10", 50000, 502, mbap(1, b"\x03\x00\x00\x00\x02")),
                   tcp("10.0.0.10", "10.0.0.20", 502, 50000, mbap(1, b"\x03\x04\x00\x01\x00\x02"),
                       src_mac=PLC_MAC, dst_mac=HMI_MAC))
        self.assertEqual(len(snap["links"]), 1)
        self.assertEqual(snap["links"][0]["packets"], 2)

    def test_device_identification_sets_vendor_model_firmware(self):
        objects = b"".join(bytes([i, len(v)]) + v for i, v in
                           ((0, b"Schneider Electric"), (1, b"BMX P34 2020"), (2, b"v3.10")))
        pdu = b"\x2b\x0e\x01\x01\x00\x00\x03" + objects
        snap = run(tcp("10.0.0.10", "10.0.0.20", 502, 50000, mbap(1, pdu), src_mac=PLC_MAC, dst_mac=HMI_MAC))
        plc = by_label(snap)["10.0.0.10"]
        self.assertEqual(plc["vendor"], "Schneider Electric")
        self.assertEqual(plc["product_code"], "BMX P34 2020")
        self.assertEqual(plc["firmware"], "v3.10")

    def test_umas_stop_raises_critical_alert_and_marks_workstation(self):
        snap = run(tcp("10.0.0.30", "10.0.0.10", 50001, 502, mbap(0, b"\x5a\x00\x41")))
        self.assertEqual(snap["alerts"][0]["severity"], "critical")
        self.assertIn("UMAS Stop PLC", snap["alerts"][0]["title"])
        self.assertEqual(by_label(snap)["10.0.0.30"]["device_type"], "Engineering workstation")

    def test_force_listen_only_alert(self):
        snap = run(tcp("10.0.0.20", "10.0.0.10", 50000, 502, mbap(1, b"\x08\x00\x04\x00\x00")))
        self.assertEqual(snap["alerts"][0]["severity"], "high")

    def test_repeated_alert_is_deduplicated(self):
        frame = tcp("10.0.0.30", "10.0.0.10", 50001, 502, mbap(0, b"\x5a\x00\x41"))
        snap = run(frame, frame, frame)
        self.assertEqual(len(snap["alerts"]), 1)
        self.assertEqual(snap["alerts"][0]["count"], 3)


class S7Tests(unittest.TestCase):
    def test_plc_stop(self):
        s7 = struct.pack("!BBHHHH", 0x32, 1, 0, 1, 16, 0) + b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM"
        snap = run(tcp("10.0.0.40", "10.0.0.11", 50100, 102, tpkt_cotp(s7)))
        self.assertEqual(snap["alerts"][0]["title"], "S7 PLC Stop 명령")
        plc = by_label(snap)["10.0.0.11"]
        self.assertEqual(plc["vendor"], "Siemens")
        self.assertEqual(plc["device_type"], "PLC (Siemens S7)")

    def test_download_block_is_requested_by_plc_but_attributed_to_workstation(self):
        # In an S7 download the PLC issues the "Download Block" job to the programming station.
        s7 = struct.pack("!BBHHHH", 0x32, 1, 0, 2, 2, 0) + b"\x1b\x00"
        snap = run(tcp("10.0.0.11", "10.0.0.40", 102, 50100, tpkt_cotp(s7), src_mac=PLC_MAC, dst_mac=HMI_MAC))
        alert = snap["alerts"][0]
        self.assertIn("다운로드", alert["title"])
        self.assertEqual((alert["src"], alert["dst"]), ("10.0.0.40", "10.0.0.11"))
        self.assertEqual(by_label(snap)["10.0.0.11"]["device_type"], "PLC (Siemens S7)")
        self.assertNotEqual(by_label(snap)["10.0.0.40"]["device_type"], "PLC (Siemens S7)")

    def test_szl_module_identification(self):
        params = b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00"
        rec1 = struct.pack("!H", 1) + b"6ES7 315-2EH14-0AB0 " + struct.pack("!HHH", 0xC0, 4, 1)
        rec2 = struct.pack("!H", 7) + b" " * 20 + struct.pack("!HHH", 0xC0, 0x5603, 0x0204)
        data = b"\xff\x09" + struct.pack("!HHHHH", 8 + 56, 0x0011, 0, 28, 2) + rec1 + rec2
        s7 = struct.pack("!BBHHHH", 0x32, 7, 0, 1, len(params), len(data)) + params + data
        snap = run(tcp("10.0.0.11", "10.0.0.40", 102, 50100, tpkt_cotp(s7), src_mac=PLC_MAC, dst_mac=HMI_MAC))
        plc = by_label(snap)["10.0.0.11"]
        self.assertEqual(plc["model"], "6ES7 315-2EH14-0AB0")
        self.assertEqual(plc["firmware"], "V3.2.4")

    def test_non_s7_iso_payload_is_mms(self):
        snap = run(tcp("10.0.0.50", "10.0.0.12", 50200, 102, tpkt_cotp(b"\x0d\x10")))
        self.assertEqual(by_label(snap)["10.0.0.12"]["device_type"], "IED (IEC 61850)")


class EnipTests(unittest.TestCase):
    def enip(self, command: int, body: bytes) -> bytes:
        return struct.pack("<HHII8sI", command, len(body), 0, 0, b"\x00" * 8, 0) + body

    def test_list_identity_response(self):
        name = b"1756-L71/B LOGIX5571"
        item = (struct.pack("<H", 1) + struct.pack(">HH", 2, 44818) + ip("10.0.0.13") + b"\x00" * 8
                + struct.pack("<HHHBBHI", 1, 0x0E, 55, 20, 11, 0x60, 0x00C0FFEE)
                + bytes([len(name)]) + name + b"\x03")
        body = struct.pack("<HHH", 1, 0x0C, len(item)) + item
        snap = run(udp("10.0.0.13", "10.0.0.20", 44818, 50000, self.enip(0x63, body),
                       src_mac=PLC_MAC, dst_mac=HMI_MAC))
        plc = by_label(snap)["10.0.0.13"]
        self.assertEqual(plc["vendor"], "Rockwell Automation/Allen-Bradley")
        self.assertEqual(plc["model"], "1756-L71/B LOGIX5571")
        self.assertEqual(plc["firmware"], "20.011")
        self.assertEqual(plc["serial"], "0x00C0FFEE")
        self.assertEqual(plc["device_type"], "PLC")

    def test_cip_reset_alert(self):
        cip = b"\x05\x02\x20\x01\x24\x01\x00"
        body = struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip)) + cip
        snap = run(tcp("10.0.0.20", "10.0.0.13", 50000, 44818, self.enip(0x6F, body)))
        self.assertEqual(snap["alerts"][0]["severity"], "critical")
        self.assertIn("Reset", snap["alerts"][0]["title"])

    def test_logix_write_tag_via_unconnected_send(self):
        inner = b"\x4d\x03\x91\x04Pump\xc1\x00\x01\x00\x01"
        cip = b"\x52\x02\x20\x06\x24\x01" + b"\x07\xe9" + struct.pack("<H", len(inner)) + inner
        body = struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0xB2, len(cip)) + cip
        snap = run(tcp("10.0.0.20", "10.0.0.13", 50000, 44818, self.enip(0x6F, body)))
        self.assertIn("CIP Write Tag", snap["links"][0]["operations"])


class PowerTests(unittest.TestCase):
    def test_dnp3_cold_restart(self):
        frame = b"\x05\x64\x08\xc4\x0a\x00\x01\x00\x00\x00" + b"\xc0\xc1\x0d" + b"\x00\x00"
        snap = run(tcp("10.0.1.1", "10.0.1.50", 50000, 20000, frame))
        self.assertEqual(snap["alerts"][0]["title"], "DNP3 Cold Restart 명령")
        self.assertEqual(by_label(snap)["10.0.1.50"]["device_type"], "RTU/IED (DNP3 outstation)")

    def test_iec104_single_command(self):
        asdu = b"\x2d\x01\x06\x00\x01\x00" + b"\x01\x00\x00\x81"
        apdu = b"\x68" + bytes([4 + len(asdu)]) + b"\x00\x00\x00\x00" + asdu
        snap = run(tcp("10.0.1.1", "10.0.1.60", 50000, 2404, apdu))
        self.assertIn("C_SC_NA_1", snap["alerts"][0]["title"])

    def test_iec104_multiple_apdus_in_segment(self):
        startdt = b"\x68\x04\x07\x00\x00\x00"
        testfr = b"\x68\x04\x43\x00\x00\x00"
        snap = run(tcp("10.0.1.1", "10.0.1.60", 50000, 2404, startdt + testfr))
        self.assertEqual(snap["links"][0]["operations"], {"STARTDT act": 1, "TESTFR act": 1})


class Layer2Tests(unittest.TestCase):
    def dcp_block(self, option: int, sub: int, value: bytes, info: bool = True) -> bytes:
        data = (b"\x00\x00" if info else b"") + value
        block = struct.pack("!BBH", option, sub, len(data)) + data
        return block + (b"\x00" if len(data) % 2 else b"")

    def test_dcp_identify_response_then_ip_traffic_merge(self):
        blocks = (self.dcp_block(2, 2, b"plc-line1") + self.dcp_block(2, 1, b"S7-1500")
                  + self.dcp_block(2, 3, b"\x00\x2a\x01\x0e")
                  + self.dcp_block(1, 2, ip("10.0.2.10") + ip("255.255.255.0") + ip("10.0.2.1")))
        dcp = struct.pack("!HBBIHH", 0xFEFF, 5, 1, 1, 0, len(blocks)) + blocks
        l2 = ether(HMI_MAC, PLC_MAC, 0x8892, dcp)
        later = tcp("10.0.2.10", "10.0.2.99", 102, 50000, b"", src_mac=PLC_MAC, dst_mac=HMI_MAC)
        snap = run(l2, later)
        plc = by_label(snap)["10.0.2.10"]
        self.assertEqual(plc["name"], "plc-line1")
        self.assertEqual(plc["model"], "S7-1500")
        self.assertEqual(plc["vendor"], "Siemens")
        self.assertEqual(plc["device_type"], "PLC (PROFINET)")
        self.assertIn(PLC_MAC, plc["macs"])
        self.assertFalse(any(a["id"].startswith("mac:") and PLC_MAC in a["macs"] for a in snap["assets"]))

    def test_dcp_factory_reset_is_critical(self):
        blocks = self.dcp_block(5, 6, b"\x00\x00", info=False)  # qualifier only
        dcp = struct.pack("!HBBIHH", 0xFEFD, 4, 0, 1, 0, len(blocks)) + blocks
        snap = run(ether(PLC_MAC, HMI_MAC, 0x8892, dcp))
        self.assertEqual(snap["alerts"][0]["severity"], "critical")

    def test_goose_publisher(self):
        ref = b"IED1LD0/LLN0$GO$gcb1"
        pdu = b"\x80" + bytes([len(ref)]) + ref + b"\x85\x01\x05\x86\x01\x00"
        goose = struct.pack("!HHHH", 0x0001, 8 + 2 + len(pdu), 0, 0) + b"\x61" + bytes([len(pdu)]) + pdu
        snap = run(ether("01:0c:cd:01:00:01", PLC_MAC, 0x88B8, goose))
        ied = snap["assets"][0]
        self.assertEqual(ied["device_type"], "IED (IEC 61850)")
        self.assertEqual(ied["name"], "IED1LD0")
        self.assertEqual(snap["links"], [])


class MelsecTests(unittest.TestCase):
    def test_slmp_remote_stop_on_custom_port(self):
        tail = b"\x10\x00" + struct.pack("<HH", 0x1002, 0) + b"\x01\x00"
        frame = b"\x50\x00\x00\xff\xff\x03\x00" + struct.pack("<H", len(tail)) + tail
        snap = run(tcp("10.0.3.5", "10.0.3.10", 50000, 5007, frame))
        self.assertEqual(snap["alerts"][0]["title"], "MELSEC PLC Remote STOP 명령")
        self.assertEqual(by_label(snap)["10.0.3.10"]["vendor"], "Mitsubishi Electric")


class EngineTests(unittest.TestCase):
    def test_arp_request_records_sender_only(self):
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(HMI_MAC) + ip("10.0.0.20") + b"\x00" * 6 + ip("10.0.0.10")
        snap = run(ether("ff:ff:ff:ff:ff:ff", HMI_MAC, 0x0806, arp))
        self.assertEqual([a["label"] for a in snap["assets"]], ["10.0.0.20"])

    def test_router_mac_is_not_attributed_to_remote_hosts(self):
        router = "00:00:5e:00:01:01"
        snap = run(udp("172.16.0.1", "10.0.0.10", 40000, 40001, b"x", src_mac=router),
                   udp("172.16.0.2", "10.0.0.10", 40000, 40001, b"x", src_mac=router))
        assets = by_label(snap)
        self.assertNotIn(router, assets["172.16.0.1"]["macs"])
        self.assertNotIn(router, assets["172.16.0.2"]["macs"])

    def test_broadcast_destination_creates_no_asset(self):
        snap = run(udp("10.0.0.20", "255.255.255.255", 44818, 44818, b"\x63\x00" + b"\x00" * 22))
        self.assertEqual([a["label"] for a in snap["assets"]], ["10.0.0.20"])

    def test_truncated_payload_does_not_crash(self):
        snap = run(tcp("10.0.0.20", "10.0.0.10", 50000, 102, b"\x03\x00\x00\x20\x02\xf0\x80\x32\x01"))
        self.assertEqual(snap["stats"]["asset_count"], 2)

    def test_port_hint_requires_reply_from_service_port(self):
        syn = tcp("10.0.0.20", "10.0.0.10", 50000, 502, b"", flags=0x02)
        synack = tcp("10.0.0.10", "10.0.0.20", 502, 50000, b"", src_mac=PLC_MAC, dst_mac=HMI_MAC, flags=0x12)
        probe = tcp("10.0.0.10", "10.0.0.20", 50001, 102, b"", src_mac=PLC_MAC, dst_mac=HMI_MAC, flags=0x02)
        rst = tcp("10.0.0.20", "10.0.0.10", 102, 50001, b"", flags=0x14)
        assets = by_label(run(syn, synack, probe, rst))
        self.assertEqual(assets["10.0.0.10"]["device_type"], "PLC candidate")
        self.assertEqual(assets["10.0.0.20"]["device_type"], "Unknown")

    def test_persistence_round_trip(self):
        store = Store(":memory:")
        engine = Engine(store)
        engine.process_raw(tcp("10.0.0.30", "10.0.0.10", 50001, 502, mbap(0, b"\x5a\x00\x41")), 1_700_000_000)
        engine.flush()
        restored = Engine(store).snapshot()
        self.assertEqual(restored["stats"]["asset_count"], 2)
        self.assertEqual(restored["alerts"][0]["count"], 1)
        self.assertEqual(restored["links"][0]["operations"], {"UMAS Stop PLC": 1})

    def test_acknowledge_and_reopen(self):
        engine = Engine()
        frame = tcp("10.0.0.30", "10.0.0.10", 50001, 502, mbap(0, b"\x5a\x00\x41"))
        engine.process_raw(frame, 1_700_000_000)
        alert_id = engine.snapshot()["alerts"][0]["id"]
        self.assertTrue(engine.acknowledge(alert_id))
        self.assertEqual(engine.snapshot()["stats"]["alert_open"], 0)
        engine.process_raw(frame, 1_700_000_100)
        self.assertEqual(engine.snapshot()["stats"]["alert_open"], 1)


if __name__ == "__main__":
    unittest.main()
