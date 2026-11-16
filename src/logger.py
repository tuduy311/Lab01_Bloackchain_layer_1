"""Stable JSONL event logging for deterministic simulator runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


class EventLog:
    """Collect ordered, JSON-ready events and write byte-stable JSONL."""

    def __init__(self) -> None:
        self.records: list[Dict[str, Any]] = []

    def append(self, event: str, *, time: float, node_id: str = "",
               height: Optional[int] = None, round: Optional[int] = None,
               **fields: Any) -> Dict[str, Any]:
        record: Dict[str, Any] = {
            "time": round_float(time),
            "event": event,
            "node_id": node_id,
            "height": height,
            "round": round,
        }
        record.update(fields)
        self.records.append(record)
        return record

    def append_network_event(self, event: Any) -> None:
        record = event.to_dict() if hasattr(event, "to_dict") else dict(event)
        self.records.append(record)

    def jsonl(self) -> bytes:
        """Serialize the event sequence with stable keys and separators."""
        return b"".join(
            (json.dumps(row, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True) + "\n").encode("utf-8")
            for row in self.records
        )

    def write(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.jsonl())

    def extend(self, records: Iterable[Dict[str, Any]]) -> None:
        self.records.extend(dict(record) for record in records)


DeterministicLogger = EventLog


def round_float(value: float) -> float:
    """Normalize simulated timestamps to the scheduler's nanosecond ticks."""
    return round(float(value), 9)
