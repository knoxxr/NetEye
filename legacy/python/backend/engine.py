"""Turns decoded frames + protocol findings into assets, communication links and alerts."""

from __future__ import annotations

import ipaddress
import time
from datetime import datetime, timezone
from threading import RLock
from typing import Any

from backend import dissectors
from backend.baseline import (
    DETECTING, GENERIC_PROTOCOLS, LEARNING, OP_SEVERITY, Baseline, link_key, op_key,
)
from backend.decode import Frame, decode
from backend.dissectors.base import CATEGORY_LABELS, CONTROL, PROGRAM, Finding
from backend.vulns import CONFIRMED, LIKELY, VulnDB, risk_level

ONLINE_WINDOW_S = 60
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
IDENTITY_FIELDS = ("vendor", "model", "firmware", "serial", "name", "product_code",
                   "device_class", "description")

# Weak fallback when only a TCP handshake / empty segment toward an OT port is seen.
PORT_HINTS = {
    ("TCP", 102): ("ISO-TSAP (S7/MMS)", "PLC/IED candidate", 0.45),
    ("TCP", 502): ("Modbus/TCP", "PLC candidate", 0.45),
    ("TCP", 44818): ("EtherNet/IP", "Industrial device candidate", 0.45),
    ("UDP", 44818): ("EtherNet/IP", "Industrial device candidate", 0.45),
    ("TCP", 20000): ("DNP3", "RTU/IED candidate", 0.45),
    ("TCP", 2404): ("IEC 60870-5-104", "RTU/IED candidate", 0.45),
    ("TCP", 4840): ("OPC UA", "OT server/gateway candidate", 0.4),
    ("UDP", 47808): ("BACnet/IP", "Building automation device", 0.5),
}


def l2_label(ethertype: int) -> str:
    if ethertype < 0x0600:
        return "802.3 LLC (STP 등)"
    return {0x86DD: "IPv6", 0x88CC: "LLDP", 0x8100: "VLAN", 0x88E5: "MACsec", 0x888E: "802.1X",
            0x88F7: "PTP"}.get(ethertype, f"L2 0x{ethertype:04X}")


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds")


def _is_unicast_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (addr.is_multicast or addr.is_unspecified or addr == ipaddress.IPv4Address("255.255.255.255")
                or ip.endswith(".255"))


def _is_unicast_mac(mac: str) -> bool:
    return bool(mac) and mac != "00:00:00:00:00:00" and not int(mac[:2], 16) & 0x01


class Engine:
    def __init__(self, store: Any | None = None, vulndb: VulnDB | None = None) -> None:
        self._lock = RLock()
        self.store = store
        self.assets: dict[str, dict[str, Any]] = {}
        self.links: dict[str, dict[str, Any]] = {}
        self.alerts: dict[str, dict[str, Any]] = {}
        self.mac_ips: dict[str, set[str]] = {}
        # (client, server, port-hint label) -> protocol identified by DPI on that conversation
        self._conversations: dict[tuple[str, str, str], str] = {}
        self._next_alert_id = 1
        self._dirty_assets: set[str] = set()
        self._dirty_links: set[str] = set()
        self._dirty_alerts: set[str] = set()
        self._deleted_assets: set[str] = set()
        self._deleted_links: set[str] = set()
        self.stats = {"frames": 0, "dissected": 0}
        self.baseline = Baseline()
        self._baseline_rewrite = False
        self.vulndb = vulndb
        if store is not None:
            self._load()
        if vulndb is not None:
            self.set_vulndb(vulndb)

    # ------------------------------------------------------------------ input
    def process_raw(self, data: bytes, ts: float) -> None:
        frame = decode(data, ts)
        if frame is not None:
            self.process(frame)

    def process(self, frame: Frame) -> None:
        try:
            findings = dissectors.dissect(frame)
        except (IndexError, ValueError, UnicodeError):  # malformed / truncated PDU
            findings = []
        with self._lock:
            self._learning()  # apply an elapsed learning window before judging this frame
            self.stats["frames"] += 1
            if findings:
                self.stats["dissected"] += 1
            self._observe(frame, findings)

    # --------------------------------------------------------------- assets
    def _observe(self, frame: Frame, findings: list[Finding]) -> None:
        now = iso(frame.ts)

        if frame.transport == "ARP":
            if _is_unicast_ip(frame.src_ip) and frame.src_ip != "0.0.0.0":
                asset = self._asset_for_ip(frame.src_ip, now)
                self._touch(asset, frame.size, now, "ARP")
                self._bind_mac(asset, frame.src_mac, frame.src_ip, now)
            return

        if frame.src_ip:
            if not _is_unicast_ip(frame.src_ip):
                return
            src = self._asset_for_ip(frame.src_ip, now)
            self._bind_mac(src, frame.src_mac, frame.src_ip, now)
            dst = self._asset_for_ip(frame.dst_ip, now) if _is_unicast_ip(frame.dst_ip) else None
            if dst is not None:
                self._bind_mac(dst, frame.dst_mac, frame.dst_ip, now)
        else:
            if not _is_unicast_mac(frame.src_mac):
                return
            src = self._asset_for_mac(frame.src_mac, now)
            dst = self._asset_for_mac(frame.dst_mac, now) if _is_unicast_mac(frame.dst_mac) else None

        if frame.vlan is not None:
            src.setdefault("vlans", set()).add(frame.vlan)

        self._touch(src, frame.size, now, None)
        if dst is not None:
            self._touch(dst, frame.size, now, None)

        if not findings:
            label = frame.transport or l2_label(frame.ethertype)
            hint = None
            if frame.src_port != frame.dst_port:
                hint = PORT_HINTS.get((frame.transport, frame.dst_port))
                server, client = dst, src
                if hint is None:
                    hint = PORT_HINTS.get((frame.transport, frame.src_port))
                    server, client = src, dst
            if hint and server is not None and client is not None:
                # Empty segments / unparsed PDUs of a conversation we already understand.
                known = self._conversations.get((client["id"], server["id"], hint[0]))
                if known:
                    for asset in (src, dst):
                        asset["protocols"].add(known)
                    self._link(client, server, known, frame.size, now, None, None)
                    return
            if hint:
                label = hint[0]
            # A service is only evidenced by traffic *from* its port (not a refused/RST probe to it).
            rst = frame.transport == "TCP" and frame.tcp_flags & 0x04
            if hint and server is src and not rst:
                self._apply_hint(server, hint[1], hint[2], f"{hint[0]} 서비스 응답 관측", now)
            for asset in (src, dst):
                if asset is not None:
                    asset["protocols"].add(label)
            if dst is not None and frame.src_ip:
                if hint and client is not None and server is not None:
                    self._link(client, server, label, frame.size, now, None, None)
                else:
                    self._link(src, dst, label, frame.size, now, None, None)
            return

        for finding in findings:
            self._apply_finding(frame, finding, src, dst, now)

    def _apply_finding(self, frame: Frame, f: Finding, src: dict, dst: dict | None, now: str) -> None:
        if f.announced_ip and _is_unicast_ip(f.announced_ip) and not frame.src_ip:
            src = self._promote_mac_asset(src, f.announced_ip, frame.src_mac, now)

        sides = {"src": src, "dst": dst}
        for asset in (src, dst):
            if asset is not None:
                asset["protocols"].add(f.protocol)
        for side, role in f.roles.items():
            if sides.get(side) is not None:
                self._add(sides[side], "roles", role)

        server = dst if f.is_request else src
        client = src if f.is_request else dst
        if f.is_request is None:
            server, client = src, dst

        if f.device_hint and server is not None:
            self._apply_hint(server, f.device_hint[0], f.device_hint[1],
                             f"{f.protocol} {('서버' if f.is_request is not None else '송신')} 동작 관측", now)
        if client is not None and f.is_request is not None and f.roles:
            if f.is_request and f.category in (PROGRAM, CONTROL):
                self._apply_hint(client, "Engineering workstation", 0.8,
                                 f"{f.protocol} {f.operation} 명령 송신", now)
            else:
                self._apply_hint(client, "SCADA/HMI/EWS candidate", 0.4,
                                 f"{f.protocol} 클라이언트 동작 관측", now)

        target = sides.get(f.identity_of)
        if f.identity and target is not None:
            changed = False
            for key in IDENTITY_FIELDS:
                value = f.identity.get(key)
                if value and target.get(key) != value:
                    previous = target.get(key)
                    target[key] = value
                    changed = True
                    if key == "firmware" and previous:
                        self._alert("high", f"펌웨어 버전 변경: {previous} → {value}", f.protocol,
                                    "Firmware change", target["id"], None, now)
            if changed:
                target["evidence"].add(f"{f.protocol} 식별 정보 응답")
                self._dirty_assets.add(target["id"])
                self._match_vulns(target, now)

        if client is not None and server is not None and frame.src_ip:
            self._link(client, server, f.protocol, frame.size, now, f.operation, f.category,
                       check_op=bool(f.is_request), explicit_alert=bool(f.alert))
            server_port = frame.dst_port if f.is_request else frame.src_port
            hint = PORT_HINTS.get((frame.transport, server_port))
            if hint:
                self._conversations[(client["id"], server["id"], hint[0])] = f.protocol
        elif dst is not None and not frame.src_ip:
            self._link(src, dst, f.protocol, frame.size, now, f.operation, f.category,
                       check_op=f.is_request is not False, explicit_alert=bool(f.alert))

        if f.alert:
            severity, title = f.alert
            # Attribute to the initiating client -> targeted server when roles are known.
            origin, target_asset = (client, server) if f.is_request is not None and client and server else (src, dst)
            self._alert(severity, title, f.protocol, f.operation, origin["id"],
                        target_asset["id"] if target_asset else None, now, f.category, f.details)

    # -------------------------------------------------------------- helpers
    def _new_asset(self, asset_id: str, ip: str, now: str) -> dict[str, Any]:
        asset = {
            "id": asset_id, "ip": ip, "macs": set(), "vlans": set(),
            "device_type": "Unknown", "confidence": 0.0,
            "vendor": "", "model": "", "firmware": "", "serial": "", "name": "",
            "product_code": "", "device_class": "", "description": "",
            "roles": set(), "protocols": set(), "evidence": set(),
            "packets": 0, "bytes": 0, "first_seen": now, "last_seen": now,
            "vulns": [], "risk": 0.0, "risk_level": "none",
        }
        self.assets[asset_id] = asset
        self._dirty_assets.add(asset_id)
        if self._learning():
            self.baseline.add("asset", asset_id)
        elif not self.baseline.has("asset", asset_id):
            internal = not ip or ipaddress.IPv4Address(ip).is_private
            title = "신규 자산 발견" if internal else "신규 외부(인터넷) 주소 관측"
            self._alert("medium", title, "", "New asset", asset_id, None, now, "",
                        baseline=("asset", asset_id))
        return asset

    def _asset_for_ip(self, ip: str, now: str) -> dict[str, Any]:
        return self.assets.get(ip) or self._new_asset(ip, ip, now)

    def _asset_for_mac(self, mac: str, now: str) -> dict[str, Any]:
        ips = self.mac_ips.get(mac)
        if ips and len(ips) == 1:
            ip = next(iter(ips))
            if ip in self.assets:
                return self.assets[ip]
        asset_id = f"mac:{mac}"
        asset = self.assets.get(asset_id)
        if asset is None:
            asset = self._new_asset(asset_id, "", now)
            asset["macs"].add(mac)
        return asset

    def _bind_mac(self, asset: dict, mac: str, ip: str, now: str) -> None:
        if not _is_unicast_mac(mac):
            return
        ips = self.mac_ips.setdefault(mac, set())
        if ip not in ips:
            ips.add(ip)
            if len(ips) == 2:
                # One MAC behind several IPs: a router/gateway. Un-attribute it from every host.
                for other_ip in ips:
                    other = self.assets.get(other_ip)
                    if other is not None and mac in other["macs"]:
                        other["macs"].discard(mac)
                        self._dirty_assets.add(other_ip)
        if len(ips) > 1:
            return
        if mac not in asset["macs"]:
            asset["macs"].add(mac)
            self._dirty_assets.add(asset["id"])
        orphan = self.assets.get(f"mac:{mac}")
        if orphan is not None:
            self._merge(orphan, asset)

    def _promote_mac_asset(self, asset: dict, ip: str, mac: str, now: str) -> dict:
        target = self._asset_for_ip(ip, now)
        self._bind_mac(target, mac, ip, now)
        if asset is not target and asset["id"] in self.assets:
            self._merge(asset, target)
        return target

    def _merge(self, source: dict, target: dict) -> None:
        for key in ("macs", "vlans", "roles", "protocols", "evidence"):
            target[key] |= source[key]
        for key in IDENTITY_FIELDS:
            if source.get(key) and not target.get(key):
                target[key] = source[key]
        if source["confidence"] > target["confidence"]:
            target["device_type"], target["confidence"] = source["device_type"], source["confidence"]
        target["packets"] += source["packets"]
        target["bytes"] += source["bytes"]
        target["first_seen"] = min(target["first_seen"], source["first_seen"])
        target["last_seen"] = max(target["last_seen"], source["last_seen"])
        old_id, new_id = source["id"], target["id"]
        del self.assets[old_id]
        self._deleted_assets.add(old_id)
        self._dirty_assets.add(new_id)
        self._match_vulns(target, target["last_seen"])
        for key, link in list(self.links.items()):
            if old_id in (link["source"], link["target"]):
                link["source"] = new_id if link["source"] == old_id else link["source"]
                link["target"] = new_id if link["target"] == old_id else link["target"]
                del self.links[key]
                self._deleted_links.add(key)
                new_key = f"{link['source']}|{link['target']}|{link['protocol']}"
                self.links[new_key] = link
                self._dirty_links.add(new_key)
        if self._rename_baseline(old_id, new_id):
            self._baseline_rewrite = True
        for alert in self.alerts.values():
            for field in ("src", "dst"):
                if alert[field] == old_id:
                    alert[field] = new_id
                    self._dirty_alerts.add(alert["key"])

    def _touch(self, asset: dict, size: int, now: str, protocol: str | None) -> None:
        asset["packets"] += 1
        asset["bytes"] += size
        if now > asset["last_seen"]:
            asset["last_seen"] = now
        if now < asset["first_seen"]:
            asset["first_seen"] = now
        if protocol:
            asset["protocols"].add(protocol)
        self._dirty_assets.add(asset["id"])

    def _add(self, asset: dict, key: str, value: str) -> None:
        if value not in asset[key]:
            asset[key].add(value)
            self._dirty_assets.add(asset["id"])

    def _apply_hint(self, asset: dict, device_type: str, confidence: float, evidence: str, now: str) -> None:
        asset["evidence"].add(evidence)
        if confidence > asset["confidence"]:
            asset["device_type"], asset["confidence"] = device_type, confidence
        self._dirty_assets.add(asset["id"])

    def _link(self, src: dict, dst: dict, protocol: str, size: int, now: str,
              operation: str | None, category: str | None,
              check_op: bool = False, explicit_alert: bool = False) -> None:
        if src is dst:
            return
        key = link_key(src["id"], dst["id"], protocol)
        link = self.links.get(key)
        if link is None:
            link = {"source": src["id"], "target": dst["id"], "protocol": protocol,
                    "packets": 0, "bytes": 0, "first_seen": now, "last_seen": now,
                    "operations": {}, "categories": {}}
            self.links[key] = link
        link["packets"] += 1
        link["bytes"] += size
        link["last_seen"] = max(link["last_seen"], now)
        if operation:
            link["operations"][operation] = link["operations"].get(operation, 0) + 1
        if category:
            link["categories"][category] = link["categories"].get(category, 0) + 1
        self._dirty_links.add(key)
        self._check_baseline(src, dst, protocol, key, now, operation if check_op else None,
                             category, explicit_alert)

    def _check_baseline(self, src: dict, dst: dict, protocol: str, key: str, now: str,
                        operation: str | None, category: str | None, explicit_alert: bool) -> None:
        learning = self._learning()
        if not self.baseline.has("link", key):
            if learning:
                self.baseline.add("link", key)
                if operation:
                    self.baseline.add("op", op_key(key, operation))
            elif not explicit_alert:  # a policy alert already covers this PDU
                generic = protocol in GENERIC_PROTOCOLS or protocol.startswith("L2 ")
                self._alert("low" if generic else "high", f"새로운 통신: {protocol}", protocol,
                            operation or "", src["id"], dst["id"], now, category or "",
                            baseline=("link", key))
            return
        if not operation:
            return
        okey = op_key(key, operation)
        if self.baseline.has("op", okey):
            return
        if learning:
            self.baseline.add("op", okey)
        elif not explicit_alert:  # a policy alert already covers this PDU
            self._alert(OP_SEVERITY.get(category or "", "low"), f"새로운 명령: {protocol} {operation}",
                        protocol, operation, src["id"], dst["id"], now, category or "",
                        baseline=("op", okey))

    def _alert(self, severity: str, title: str, protocol: str, operation: str,
               src: str, dst: str | None, now: str, category: str = "", details: dict | None = None,
               baseline: tuple[str, str] | None = None) -> None:
        key = f"{title}|{src}|{dst}"
        alert = self.alerts.get(key)
        if alert is None:
            alert = {"id": self._next_alert_id, "key": key, "severity": severity, "title": title,
                     "protocol": protocol, "operation": operation, "category": category,
                     "category_label": CATEGORY_LABELS.get(category, ""),
                     "src": src, "dst": dst, "count": 0, "first_seen": now, "last_seen": now,
                     "status": "new", "source": "baseline" if baseline else "policy",
                     "baseline": {"kind": baseline[0], "key": baseline[1]} if baseline else None,
                     "details": {k: v for k, v in (details or {}).items()
                                                  if isinstance(v, (str, int, float, bool))}}
            self._next_alert_id += 1
            self.alerts[key] = alert
        alert["count"] += 1
        alert["last_seen"] = max(alert["last_seen"], now)
        if alert["status"] == "acknowledged" and alert["last_seen"] == now:
            alert["status"] = "new"  # re-opened by recurrence
        self._dirty_alerts.add(key)

    # --------------------------------------------------------------- output
    def acknowledge(self, alert_id: int) -> bool:
        with self._lock:
            for alert in self.alerts.values():
                if alert["id"] == alert_id:
                    alert["status"] = "acknowledged"
                    self._dirty_alerts.add(alert["key"])
                    return True
        return False

    # -------------------------------------------------------- vulnerabilities
    def set_vulndb(self, vulndb: VulnDB | None) -> None:
        with self._lock:
            self.vulndb = vulndb
            for asset in self.assets.values():
                self._match_vulns(asset, asset["last_seen"])

    def _match_vulns(self, asset: dict, now: str) -> None:
        if self.vulndb is None or not (asset.get("vendor") or asset.get("model")):
            vulns: list[dict] = []
        else:
            vulns = self.vulndb.match(asset)
        risk = max((v["score"] for v in vulns), default=0.0)
        if vulns == asset.get("vulns") and risk == asset.get("risk"):
            return
        asset["vulns"], asset["risk"], asset["risk_level"] = vulns, risk, risk_level(risk)
        self._dirty_assets.add(asset["id"])
        solid = [v for v in vulns if v["level"] in (CONFIRMED, LIKELY)]
        kev = [v for v in solid if v["kev"]]
        if kev:
            self._alert_once("critical", "악용 중인 취약점(KEV) 보유 자산", asset["id"], now,
                             {"advisories": ", ".join(v["id"] for v in kev[:5])})
        elif any(v["level"] == CONFIRMED and (v["cvss"] or 0) >= 9 for v in solid):
            self._alert_once("high", "치명적(CVSS 9+) 취약점 보유 자산", asset["id"], now,
                             {"advisories": ", ".join(v["id"] for v in solid if (v["cvss"] or 0) >= 9)})

    def _alert_once(self, severity: str, title: str, asset_id: str, now: str, details: dict) -> None:
        if f"{title}|{asset_id}|None" not in self.alerts:
            self._alert(severity, title, "", "Vulnerability", asset_id, None, now, "", details)

    def learn_alert(self, alert_id: int) -> bool:
        """Accept the behaviour behind a baseline alert as normal."""
        with self._lock:
            for alert in self.alerts.values():
                if alert["id"] != alert_id:
                    continue
                item = alert.get("baseline")
                if item:
                    self.baseline.add(item["kind"], item["key"])
                    if item["kind"] == "link" and item["key"] in self.links:
                        for operation in self.links[item["key"]]["operations"]:
                            self.baseline.add("op", op_key(item["key"], operation))
                alert["status"] = "acknowledged"
                self._dirty_alerts.add(alert["key"])
                return True
        return False

    def set_mode(self, mode: str, hours: float | None = None, reset: bool = False) -> dict:
        with self._lock:
            if reset:
                self.baseline.clear()
                self._baseline_rewrite = True
            if mode == DETECTING:
                # Everything observed so far (including inventory restored from disk) is normal.
                for asset_id in self.assets:
                    self.baseline.add("asset", asset_id)
                for key, link in self.links.items():
                    self.baseline.add("link", key)
                    for operation in link["operations"]:
                        self.baseline.add("op", op_key(key, operation))
            self.baseline.set_mode(mode, hours)
            return self.baseline.status()

    def _learning(self) -> bool:
        b = self.baseline
        if b.mode == LEARNING and b.learning_until and time.time() >= b.learning_until:
            self.set_mode(DETECTING)  # learning window elapsed: freeze what was seen
        return self.baseline.mode == LEARNING

    def _rename_baseline(self, old_id: str, new_id: str) -> bool:
        changed = False
        for keys in self.baseline.items.values():
            for key in [k for k in keys if old_id in k.split("|")]:
                keys.discard(key)
                keys.add("|".join(new_id if part == old_id else part for part in key.split("|")))
                changed = True
        return changed

    @staticmethod
    def _serialize_asset(asset: dict) -> dict:
        item = dict(asset)
        for key in ("macs", "vlans", "roles", "protocols", "evidence"):
            item[key] = sorted(asset[key])
        return item

    def snapshot(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        with self._lock:
            assets = []
            for asset in self.assets.values():
                item = self._serialize_asset(asset)
                age = (now - datetime.fromisoformat(asset["last_seen"])).total_seconds()
                item["status"] = "online" if age <= ONLINE_WINDOW_S else "stale"
                item["label"] = asset["ip"] or asset["name"] or next(iter(sorted(asset["macs"])), asset["id"])
                assets.append(item)
            links = [{**link, "operations": dict(link["operations"]),
                      "categories": dict(link["categories"])} for link in self.links.values()]
            alerts = sorted((dict(a) for a in self.alerts.values()),
                            key=lambda a: (a["status"] != "new", -SEVERITY_RANK[a["severity"]], a["last_seen"]),
                            reverse=False)
            stats = dict(self.stats)
        assets.sort(key=lambda a: tuple(int(p) for p in a["ip"].split(".")) if a["ip"] else (999, a["id"]))
        links.sort(key=lambda l: (l["source"], l["target"], l["protocol"]))
        open_alerts = [a for a in alerts if a["status"] == "new"]
        with self._lock:
            self._learning()
            baseline = self.baseline.status()
        return {
            "assets": assets,
            "links": links,
            "alerts": alerts[:500],
            "baseline": baseline,
            "vulndb": self.vulndb.info() if self.vulndb else None,
            "stats": {
                **stats,
                "asset_count": len(assets),
                "ot_asset_count": sum(a["device_type"] != "Unknown" for a in assets),
                "link_count": len(links),
                "alert_open": len(open_alerts),
                "alert_critical": sum(a["severity"] in ("critical", "high") for a in open_alerts),
                "vulnerable_assets": sum(1 for a in assets if any(v["level"] != "possible" for v in a["vulns"])),
                "kev_assets": sum(1 for a in assets if any(v["kev"] and v["level"] != "possible"
                                                           for v in a["vulns"])),
            },
        }

    # ---------------------------------------------------------- persistence
    def _load(self) -> None:
        meta, items = self.store.load_baseline()
        self.baseline.restore(meta, items)
        assets, links, alerts = self.store.load()
        for asset in assets:
            for key in ("macs", "vlans", "roles", "protocols", "evidence"):
                asset[key] = set(asset.get(key, []))
            asset.pop("status", None)
            asset.pop("label", None)
            asset.setdefault("vulns", [])
            asset.setdefault("risk", 0.0)
            asset.setdefault("risk_level", "none")
            self.assets[asset["id"]] = asset
            for mac in asset["macs"]:
                if asset["ip"]:
                    self.mac_ips.setdefault(mac, set()).add(asset["ip"])
        for link in links:
            self.links[f"{link['source']}|{link['target']}|{link['protocol']}"] = link
        for alert in alerts:
            alert.setdefault("source", "policy")
            alert.setdefault("baseline", None)
            self.alerts[alert["key"]] = alert
            self._next_alert_id = max(self._next_alert_id, alert["id"] + 1)

    def flush(self) -> None:
        if self.store is None:
            return
        with self._lock:
            assets = [self._serialize_asset(self.assets[i]) for i in self._dirty_assets if i in self.assets]
            links = [(k, {**self.links[k], "operations": dict(self.links[k]["operations"]),
                          "categories": dict(self.links[k]["categories"])})
                     for k in self._dirty_links if k in self.links]
            alerts = [{**self.alerts[k], "details": dict(self.alerts[k]["details"])}
                      for k in self._dirty_alerts if k in self.alerts]
            deleted_assets = list(self._deleted_assets)
            deleted_links = [k for k in self._deleted_links if k not in self.links]
            self._dirty_assets.clear()
            self._dirty_links.clear()
            self._dirty_alerts.clear()
            self._deleted_assets.clear()
            self._deleted_links.clear()
            rewrite = self._baseline_rewrite
            baseline_items = ([(k, key) for k, keys in self.baseline.items.items() for key in keys]
                              if rewrite else list(self.baseline.pending))
            self.baseline.pending.clear()
            self._baseline_rewrite = False
            meta = self.baseline.meta() if self.baseline.meta_dirty else None
            self.baseline.meta_dirty = False
        self.store.save(assets, links, alerts, deleted_assets, deleted_links)
        self.store.save_baseline(baseline_items, rewrite, meta)
