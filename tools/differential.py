"""Differential test: the Rust sensor must reproduce the legacy Python reference engine exactly.

Feeds identical captures to both implementations and compares every asset, link, alert, baseline
count and vulnerability match. Use it whenever detection logic changes.

    python tools/differential.py <pcap-dir> [--vulndb vulndb.json] [--neteye sensor/target/release/neteye]

Requires the legacy engine's dependency (scapy) for the Python side: pip install -r legacy/python/requirements.txt
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "legacy" / "python"))

from backend.capture import import_pcap  # noqa: E402
from backend.engine import Engine  # noqa: E402
from backend.vulns import VulnDB  # noqa: E402

ASSET_FIELDS = ["device_type", "vendor", "model", "firmware", "serial", "name", "product_code", "device_class",
                "description", "macs", "vlans", "roles", "protocols", "evidence", "packets", "bytes",
                "first_seen", "last_seen", "risk", "risk_level", "label", "ip"]
LINK_FIELDS = ["packets", "bytes", "first_seen", "last_seen", "operations", "categories"]
ALERT_FIELDS = ["severity", "title", "protocol", "operation", "category", "category_label", "src", "dst", "count",
                "first_seen", "last_seen", "status", "source", "baseline"]
STAT_FIELDS = ["frames", "dissected", "asset_count", "ot_asset_count", "link_count", "alert_open", "alert_critical",
               "vulnerable_assets", "kev_assets"]


def normalize(snap: dict) -> dict:
    # Statistical anomaly alerts exist only in the Rust sensor (the reference engine predates them):
    # compare everything else, and recount the open-alert stats without them.
    anomaly = [a for a in snap["alerts"] if a.get("source") == "anomaly"]
    if anomaly:
        snap = {**snap, "alerts": [a for a in snap["alerts"] if a.get("source") != "anomaly"],
                "stats": {**snap["stats"],
                          "alert_open": snap["stats"]["alert_open"] - sum(a["status"] == "new" for a in anomaly),
                          "alert_critical": snap["stats"]["alert_critical"] - sum(
                              a["status"] == "new" and a["severity"] in ("critical", "high") for a in anomaly)}}
    assets = {}
    for a in snap["assets"]:
        item = {k: a[k] for k in ASSET_FIELDS}
        item["confidence"] = round(a["confidence"], 3)
        item["vulns"] = sorted((v["id"], v["level"], v["score"], v["kev"]) for v in a["vulns"])
        assets[a["id"]] = item
    return {
        "assets": assets,
        "links": {f"{l['source']}|{l['target']}|{l['protocol']}": {k: l[k] for k in LINK_FIELDS} for l in snap["links"]},
        "alerts": {a["key"]: {k: a[k] for k in ALERT_FIELDS} for a in snap["alerts"]},
        "stats": {k: snap["stats"][k] for k in STAT_FIELDS},
        "baseline": snap["baseline"]["counts"],
    }


def python_run(steps: list[str], vulndb: str | None) -> dict:
    engine = Engine(vulndb=VulnDB.load(vulndb) if vulndb else None)
    for step in steps:
        if step == "--detect":
            engine.set_mode("detecting")
        else:
            import_pcap(step, engine)
    return normalize(engine.snapshot())


def rust_run(binary: str, steps: list[str], vulndb: str | None) -> dict:
    cmd = [binary, "replay"] + (["--vulndb", vulndb] if vulndb else []) + steps
    return normalize(json.loads(subprocess.run(cmd, capture_output=True, check=True).stdout))


def diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        problems = []
        for key in sorted(set(a) | set(b), key=str):
            if key not in a:
                problems.append(f"{path}/{key}: only in rust")
            elif key not in b:
                problems.append(f"{path}/{key}: only in python")
            else:
                problems += diff(a[key], b[key], f"{path}/{key}")
        return problems
    return [] if a == b else [f"{path}: python={a!r} rust={b!r}"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pcaps", help="directory of .pcap files")
    parser.add_argument("--vulndb", help="vulndb.json for the vulnerability scenario")
    default_bin = ROOT / "sensor" / "target" / "release" / ("neteye.exe" if os.name == "nt" else "neteye")
    parser.add_argument("--neteye", default=str(default_bin))
    args = parser.parse_args()

    files = sorted(glob.glob(os.path.join(args.pcaps, "*.pcap")))
    named = {os.path.basename(f): f for f in files}
    scenarios = [(os.path.basename(f), [f], None) for f in files]
    scenarios.append(("all captures in one engine", files, None))
    for learn, detect in (("modbus_test_data_part1.pcap", "modbus_test_data_part2.pcap"),
                          ("dnp3_test_data_part1.pcap", "dnp3_test_data_part2.pcap")):
        if learn in named and detect in named:
            scenarios.append((f"baseline {learn} -> {detect}", [named[learn], "--detect", named[detect]], None))
    if args.vulndb:
        scenarios.append(("vulnerability matching, all captures", files, args.vulndb))

    failures = 0
    for name, steps, vulndb in scenarios:
        py, rs = python_run(steps, vulndb), rust_run(args.neteye, steps, vulndb)
        problems = diff(py, rs)
        size = f"{len(py['assets'])} assets / {len(py['links'])} links / {len(py['alerts'])} alerts"
        if problems:
            failures += 1
            print(f"FAIL {name} ({size}): {len(problems)} differences")
            for problem in problems[:12]:
                print("    ", problem)
        else:
            print(f"ok   {name} ({size})")
    print(f"\n{len(scenarios) - failures}/{len(scenarios)} scenarios identical")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
