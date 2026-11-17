"""Canonical, replayable logging for the deterministic simulator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Mapping


def canonical_event(event: Mapping[str, object]) -> bytes:
    """Encode one event without whitespace or platform-dependent formatting."""
    return json.dumps(
        dict(event), ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def canonical_log_bytes(events: Iterable[Mapping[str, object]]) -> bytes:
    """Return the byte representation used for T8 comparisons."""
    records = [canonical_event(event) for event in events]
    return b"".join(record + b"\n" for record in records)


def write_log(path: str | Path, events: Iterable[Mapping[str, object]]) -> str:
    """Write a canonical JSONL log and return its SHA-256 digest."""
    import hashlib

    payload = canonical_log_bytes(events)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def state_hashes_are_equal(state_hashes: Mapping[str, str]) -> bool:
    """Check that every node reports the same committed state hash."""
    return len(set(state_hashes.values())) <= 1
