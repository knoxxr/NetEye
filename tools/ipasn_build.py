"""Download the IP-to-ASN database used to name internet addresses (organisation, AS number, country).

Source: iptoasn.com `ip2asn-v4.tsv.gz` (Public Domain, PDDL v1.0), updated hourly upstream.
The sensor reads the compressed file directly; nothing is ever looked up online at run time.

    python tools/ipasn_build.py [--out data/ip2asn-v4.tsv.gz]
"""
import argparse
import gzip
import os
import sys
import tempfile
import urllib.request

URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"


def main() -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=os.path.join(root, "data", "ip2asn-v4.tsv.gz"))
    args = parser.parse_args()
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    request = urllib.request.Request(URL, headers={"User-Agent": "NetEye-intel-builder"})
    fd, temp = tempfile.mkstemp(suffix=".gz", dir=os.path.dirname(os.path.abspath(args.out)))
    try:
        with urllib.request.urlopen(request, timeout=120) as response, os.fdopen(fd, "wb") as out:
            while chunk := response.read(1 << 20):
                out.write(chunk)
        # Validate before replacing the current file: it must decompress and look like the format.
        ranges = 0
        with gzip.open(temp, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.rstrip("\n").split("\t")
                if len(fields) >= 5 and fields[2].isdigit():
                    ranges += 1
        if ranges < 100_000:
            raise ValueError(f"unexpected content ({ranges} ranges)")
        os.replace(temp, args.out)
    except Exception as e:  # keep the previous file on any failure
        try:
            os.remove(temp)
        except OSError:
            pass
        print(f"failed: {e}", file=sys.stderr)
        return 1
    print(f"{args.out}: {ranges:,} ranges ({os.path.getsize(args.out) / 1e6:.1f} MB)")
    print("Restart the sensor to load it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
