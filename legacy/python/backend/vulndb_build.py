"""Moved to tools/vulndb_build.py; re-exported for the legacy reference engine and its tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from vulndb_build import build, convert, iter_csaf_dir, iter_csaf_tar, main  # noqa: E402,F401
