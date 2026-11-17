"""Build the pinned BangDB server next to the NetEye sensor binary.

NetEye stores its data in BangDB (github.com/knoxxr/bangdb) and starts the `bangdb` executable it
finds next to `neteye`. This installs the pinned release with the same version stamping as BangDB's
own scripts/build.sh, so `/health` reports the real version.

    python tools/build_bangdb.py                     # -> sensor/target/release/bangdb[.exe]
    python tools/build_bangdb.py --out dist --version v0.7.73

Requires Go 1.22+. CGO is disabled: BangDB is pure Go.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

PINNED = "v0.7.73"
MODULE = "github.com/knoxxr/bangdb"


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", default=PINNED, help=f"BangDB release tag (default {PINNED})")
    parser.add_argument("--out", type=Path, default=root / "sensor" / "target" / "release")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    plain = args.version.lstrip("v")
    ldflags = f"-s -w -X {MODULE}.Version={plain}"
    env = {**os.environ, "GOBIN": str(args.out.resolve()), "CGO_ENABLED": "0"}
    cmd = ["go", "install", "-trimpath", "-ldflags", ldflags, f"{MODULE}/cmd/bangdb@{args.version}"]
    print(" ".join(cmd), file=sys.stderr)
    subprocess.run(cmd, env=env, check=True)
    exe = args.out / ("bangdb.exe" if os.name == "nt" else "bangdb")
    print(subprocess.run([str(exe), "-version"], capture_output=True, text=True).stdout.strip() or exe)
    return 0


if __name__ == "__main__":
    sys.exit(main())
