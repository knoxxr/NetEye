"""Packet sources: live passive capture (scapy) and offline PCAP/PCAPNG import."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from backend.engine import Engine

DLT_EN10MB = 1


def start_capture(interface: str, engine: Engine):
    from scapy.all import AsyncSniffer  # imported lazily: scapy is slow to import

    def handle(packet) -> None:
        engine.process_raw(bytes(packet), float(getattr(packet, "time", time.time())))

    sniffer = AsyncSniffer(iface=interface, store=False, prn=handle)
    sniffer.start()
    return sniffer


def import_pcap(path: str | Path, engine: Engine,
                progress: Callable[[int], None] | None = None) -> dict[str, int]:
    """Feed every Ethernet frame in a pcap/pcapng file through the engine."""
    from scapy.utils import RawPcapReader

    frames = skipped = 0
    with RawPcapReader(str(path)) as reader:
        linktype = getattr(reader, "linktype", DLT_EN10MB)
        for data, meta in reader:
            if linktype != DLT_EN10MB and getattr(meta, "linktype", linktype) != DLT_EN10MB:
                skipped += 1
                continue
            if hasattr(meta, "sec"):
                ts = meta.sec + meta.usec / 1_000_000
            else:  # pcapng metadata
                ts = ((meta.tshigh << 32) | meta.tslow) / float(getattr(meta, "tsresol", 1_000_000))
            engine.process_raw(data, ts)
            frames += 1
            if progress and frames % 5000 == 0:
                progress(frames)
    engine.flush()
    return {"frames": frames, "skipped": skipped}


if __name__ == "__main__":  # python -m backend.capture file.pcap [db]
    import json
    import sys

    from backend.storage import Store

    if len(sys.argv) < 2:
        sys.exit("usage: python -m backend.capture <file.pcap> [neteye.db]")
    store = Store(sys.argv[2]) if len(sys.argv) > 2 else None
    engine = Engine(store)
    result = import_pcap(sys.argv[1], engine, lambda n: print(f"{n} frames...", file=sys.stderr))
    snap = engine.snapshot()
    print(json.dumps({"import": result, "stats": snap["stats"],
                      "assets": [{k: a[k] for k in ("label", "device_type", "vendor", "model", "firmware",
                                                    "protocols")} for a in snap["assets"]],
                      "alerts": [{k: a[k] for k in ("severity", "title", "src", "dst", "count")}
                                 for a in snap["alerts"]]}, ensure_ascii=False, indent=2))
