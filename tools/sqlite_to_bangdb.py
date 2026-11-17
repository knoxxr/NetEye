"""Move an existing NetEye SQLite database (earlier versions) into BangDB.

Assets, communications, alerts, baseline, accounts and the audit log are copied as they are; the
table layout did not change. Uses BangDB's own importer, which reads SQLite `.dump` output.

    python tools/sqlite_to_bangdb.py data/neteye.db data/neteye.bdb

Stop the sensor first. The target must not exist yet. Needs the bangdb executable
(next to neteye, on PATH, or --bangdb PATH).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


def find_bangdb(explicit: str | None) -> str:
    if explicit:
        return explicit
    name = "bangdb.exe" if os.name == "nt" else "bangdb"
    local = Path(__file__).resolve().parents[1] / "sensor" / "target" / "release" / name
    return str(local) if local.is_file() else (shutil.which("bangdb") or sys.exit("bangdb executable not found"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sqlite_db", type=Path)
    parser.add_argument("bangdb_db", type=Path)
    parser.add_argument("--bangdb", help="path to the bangdb executable")
    args = parser.parse_args()
    if not args.sqlite_db.is_file():
        sys.exit(f"{args.sqlite_db}: not found")
    if args.bangdb_db.exists():
        sys.exit(f"{args.bangdb_db}: already exists; refusing to overwrite")

    source = sqlite3.connect(f"file:{args.sqlite_db}?mode=ro", uri=True)
    counts = {t: source.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for (t,) in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False, encoding="utf-8") as dump:
        for line in source.iterdump():
            dump.write(line + "\n")
    source.close()

    args.bangdb_db.parent.mkdir(parents=True, exist_ok=True)
    try:
        # The shell reads commands from stdin; `.read` imports the whole dump in one transaction.
        result = subprocess.run([find_bangdb(args.bangdb), str(args.bangdb_db)], input=f".read {dump.name}\n",
                                capture_output=True, text=True)
    finally:
        os.unlink(dump.name)
    if result.returncode != 0 or "error" in result.stderr.lower():
        sys.stderr.write(result.stdout + result.stderr)
        return 1
    print(result.stdout.strip())
    for table, n in sorted(counts.items()):
        print(f"  {table}: {n} rows")
    print(f"done: {args.bangdb_db}  (start the sensor with NETEYE_DB={args.bangdb_db})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
