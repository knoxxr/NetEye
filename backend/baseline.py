"""Behavioural baseline: what was observed during learning is 'normal'; deviations raise alerts.

Three granularities are tracked, mirroring how OT monitors model a process network:
  asset  - every host / L2 station that exists
  link   - client -> server conversation per protocol
  op     - each operation (function code / command) used on a conversation
"""

from __future__ import annotations

import time
from typing import Any

from backend.dissectors.base import (
    COMMAND, CONFIG, CONTROL, DIAGNOSTIC, DISCOVERY, FIRMWARE, PROGRAM, WRITE,
)

LEARNING = "learning"
DETECTING = "detecting"

# Transport-level labels: a new conversation of this kind is low severity.
GENERIC_PROTOCOLS = {"TCP", "UDP", "ICMP", "ARP", "IPv6", "LLDP", "802.3 LLC (STP 등)"}

OP_SEVERITY = {
    CONTROL: "high", PROGRAM: "high", FIRMWARE: "high", CONFIG: "high", COMMAND: "high",
    WRITE: "medium", DISCOVERY: "medium", DIAGNOSTIC: "medium",
}


def link_key(client: str, server: str, protocol: str) -> str:
    return f"{client}|{server}|{protocol}"


def op_key(link: str, operation: str) -> str:
    return f"{link}|{operation}"


class Baseline:
    def __init__(self) -> None:
        self.items: dict[str, set[str]] = {"asset": set(), "link": set(), "op": set()}
        self.mode = LEARNING
        self.mode_since = time.time()
        self.learning_until: float | None = None
        self.pending: list[tuple[str, str]] = []   # additions not yet persisted
        self.meta_dirty = True

    # ---------------------------------------------------------------- state
    def learning(self) -> bool:
        if self.mode == LEARNING and self.learning_until and time.time() >= self.learning_until:
            self.set_mode(DETECTING)
        return self.mode == LEARNING

    def set_mode(self, mode: str, hours: float | None = None) -> None:
        if mode not in (LEARNING, DETECTING):
            raise ValueError(f"unknown mode {mode!r}")
        self.mode = mode
        self.mode_since = time.time()
        self.learning_until = self.mode_since + hours * 3600 if mode == LEARNING and hours else None
        self.meta_dirty = True

    def clear(self) -> None:
        for bucket in self.items.values():
            bucket.clear()
        self.pending.clear()

    def has(self, kind: str, key: str) -> bool:
        return key in self.items[kind]

    def add(self, kind: str, key: str) -> bool:
        if key in self.items[kind]:
            return False
        self.items[kind].add(key)
        self.pending.append((kind, key))
        return True

    # ---------------------------------------------------------- persistence
    def meta(self) -> dict[str, Any]:
        return {"mode": self.mode, "mode_since": self.mode_since, "learning_until": self.learning_until}

    def restore(self, meta: dict[str, Any] | None, items: list[tuple[str, str]]) -> None:
        for kind, key in items:
            self.items.setdefault(kind, set()).add(key)
        if meta:
            self.mode = meta.get("mode", LEARNING)
            self.mode_since = meta.get("mode_since") or time.time()
            self.learning_until = meta.get("learning_until")
        self.meta_dirty = False

    def status(self) -> dict[str, Any]:
        self.learning()  # apply expiry
        return {**self.meta(), "counts": {kind: len(keys) for kind, keys in self.items.items()}}
