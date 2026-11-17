"""Build the threat list the sensor checks every internet address against (data/blocklist.txt).

Sources (free, no account needed):
  - abuse.ch Feodo Tracker botnet C2 servers   https://feodotracker.abuse.ch/  (CC0)
  - Spamhaus DROP (hijacked / criminal netblocks) https://www.spamhaus.org/drop/
Entries from data/blocklist_custom.txt (one address or network per line, optional `# note`)
are added as well, so site-specific indicators survive a rebuild.

    python tools/threatintel_build.py [--out data/blocklist.txt]
"""
import argparse
import datetime
import ipaddress
import json
import os
import sys
import urllib.request

FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
DROP = "https://www.spamhaus.org/drop/drop_v4.json"


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "NetEye-intel-builder"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", errors="replace")


def feodo() -> list[str]:
    out = []
    for line in fetch(FEODO).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(str(ipaddress.IPv4Address(line)))
    return out


def drop() -> list[str]:
    out = []
    for line in fetch(DROP).splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        if "cidr" in item:
            out.append(str(ipaddress.IPv4Network(item["cidr"], strict=False)))
    return out


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=os.path.join(root, "data", "blocklist.txt"))
    parser.add_argument("--custom", default=os.path.join(root, "data", "blocklist_custom.txt"))
    args = parser.parse_args()

    lines = [f"# NetEye threat list, built {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M} UTC",
             "# address[/prefix]  # source"]
    counts = {}
    for name, loader in (("Feodo Tracker", feodo), ("Spamhaus DROP", drop)):
        try:
            entries = loader()
        except Exception as e:
            print(f"{name}: skipped ({e})", file=sys.stderr)
            continue
        counts[name] = len(entries)
        lines += [f"{entry}  # {name}" for entry in entries]
    if os.path.exists(args.custom):
        custom = 0
        for line in open(args.custom, encoding="utf-8"):
            spec = line.split("#")[0].strip()
            if spec:
                ipaddress.IPv4Network(spec, strict=False)  # validate
                note = line.split("#", 1)[1].strip() if "#" in line else "사용자 목록"
                lines.append(f"{spec}  # {note}")
                custom += 1
        counts["custom"] = custom
    if not any(counts.values()):
        print("no entries downloaded; keeping the existing list", file=sys.stderr)
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    temp = args.out + ".tmp"
    with open(temp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(temp, args.out)
    print(f"{args.out}: " + ", ".join(f"{k} {v:,}" for k, v in counts.items()))
    print("Restart the sensor to load it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
