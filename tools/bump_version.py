#!/usr/bin/env python3
"""Bump the NetEye version in sensor/Cargo.toml (used by all 4 platform installers).

    python3 tools/bump_version.py 0.2.0
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CARGO = ROOT / "sensor" / "Cargo.toml"


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", sys.argv[1]):
        print("Usage: python3 tools/bump_version.py <semver>  (e.g. 0.2.0)", file=sys.stderr)
        return 2
    new_ver = sys.argv[1]
    text = CARGO.read_text(encoding="utf-8")
    updated, count = re.subn(r'^(version\s*=\s*)"[^"]+"', rf'\1"{new_ver}"', text, count=1, flags=re.M)
    if count != 1:
        print("Could not locate version field in sensor/Cargo.toml", file=sys.stderr)
        return 1
    CARGO.write_text(updated, encoding="utf-8")
    print(f"Updated sensor/Cargo.toml -> v{new_ver}")
    print(f"Next: git commit -am 'chore: release v{new_ver}' && git tag v{new_ver} && git push origin main v{new_ver}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
