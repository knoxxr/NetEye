from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Operation categories, ordered roughly by operational risk.
READ = "read"
MONITOR = "monitor"          # cyclic / spontaneous process data
SESSION = "session"          # connection setup, keep-alive
DISCOVERY = "discovery"      # identity queries, device scans
DIAGNOSTIC = "diagnostic"
WRITE = "write"              # process value / setpoint writes
COMMAND = "command"          # operate a breaker, valve, output
CONFIG = "config"            # device configuration changes
PROGRAM = "program"          # logic upload/download, block changes
CONTROL = "control"          # CPU run/stop, restart, reset
FIRMWARE = "firmware"

CATEGORY_LABELS = {
    READ: "읽기", MONITOR: "모니터링", SESSION: "세션", DISCOVERY: "탐색",
    DIAGNOSTIC: "진단", WRITE: "쓰기", COMMAND: "제어 명령", CONFIG: "설정 변경",
    PROGRAM: "프로그램 변경", CONTROL: "운전 상태 제어", FIRMWARE: "펌웨어",
}


@dataclass
class Finding:
    """What a dissector understood about one PDU."""

    protocol: str
    operation: str = ""
    category: str = ""
    is_request: bool | None = None   # True: src is client/master, False: src is server
    function_code: int | None = None
    # Identity attributes learned about one endpoint ("src" or "dst").
    identity: dict[str, Any] = field(default_factory=dict)
    identity_of: str = "src"
    # Role hints: e.g. {"src": "S7 client", "dst": "S7 server"}
    roles: dict[str, str] = field(default_factory=dict)
    # Device class hint for the server/publisher side, with confidence.
    device_hint: tuple[str, float] | None = None
    details: dict[str, Any] = field(default_factory=dict)
    # Optional explicit alert request: (severity, title)
    alert: tuple[str, str] | None = None
    # For L2 discovery protocols that announce an IP for the source MAC.
    announced_ip: str | None = None
