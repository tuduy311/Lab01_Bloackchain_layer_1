"""Outbound rate limiting and peer blocking.

Lab01 §6 requires each node to *limit outbound rate* and to *temporarily block
overactive peers*, and it requires that the events ``block`` / ``unblock`` be
logged.  Two independent mechanisms are implemented here:

``TokenBucket``
    Sender side, one bucket per ``(sender, recipient)`` link.  Excess messages
    are dropped instead of queued, which is what a real node does when an
    application floods the peer link.

``InboundRateTracker`` + ``PeerBlockList``
    Receiver side.  A peer that exceeds ``inbound_capacity`` messages inside
    ``inbound_window`` seconds is added to the blocklist for
    ``peer_block_duration`` seconds.  While blocked, both in-flight and new
    messages from that peer are dropped.  :class:`src.network.network.Network`
    schedules the matching ``UNBLOCK`` event.

All state is plain deterministic arithmetic on simulation time: no wall clock,
no randomness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class RateLimitPolicy:
    """Thresholds for the two rate-limiting mechanisms.

    Parameters
    ----------
    capacity : int
        Burst size of the outbound token bucket per link.
    refill_per_second : float
        Tokens added to an outbound bucket per simulated second.
    inbound_capacity : int
        Messages a peer may send inside one inbound window before it is
        considered overactive.
    inbound_window : float
        Length of the inbound counting window in seconds.
    peer_block_duration : float
        How long an overactive peer stays blocked, in seconds.
    """

    capacity: int = 32
    refill_per_second: float = 64.0
    inbound_capacity: int = 64
    inbound_window: float = 1.0
    peer_block_duration: float = 2.0

    def validate(self) -> List[str]:
        """Return a list of configuration problems (empty when valid)."""
        problems: List[str] = []
        if self.capacity < 1:
            problems.append("rate limit capacity must be >= 1")
        if self.refill_per_second <= 0:
            problems.append("rate limit refill_per_second must be > 0")
        if self.inbound_capacity < 1:
            problems.append("inbound_capacity must be >= 1")
        if self.inbound_window <= 0:
            problems.append("inbound_window must be > 0")
        if self.peer_block_duration < 0:
            problems.append("peer_block_duration must be >= 0")
        return problems


class TokenBucket:
    """Classic token bucket with continuous refill.

    The bucket starts full so a quiet link can burst immediately.
    """

    def __init__(
        self,
        capacity: float,
        refill_per_second: float,
        start_time: float = 0.0,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be > 0")
        if refill_per_second <= 0:
            raise ValueError("refill_per_second must be > 0")
        self.capacity = float(capacity)
        self.refill_per_second = float(refill_per_second)
        self._tokens = float(capacity)
        self._last_refill = float(start_time)

    def _refill(self, now: float) -> None:
        if now > self._last_refill:
            self._tokens = min(
                self.capacity,
                self._tokens + (now - self._last_refill) * self.refill_per_second,
            )
            self._last_refill = now

    def allow(self, now: float, cost: float = 1.0) -> bool:
        """Consume *cost* tokens if available; return whether it succeeded."""
        self._refill(now)
        if self._tokens >= cost:
            self._tokens -= cost
            return True
        return False

    def available(self, now: float) -> float:
        """Current number of tokens (after refilling to *now*)."""
        self._refill(now)
        return self._tokens


class InboundRateTracker:
    """Fixed-window counter of inbound messages per peer."""

    def __init__(self, capacity: int, window: float) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        if window <= 0:
            raise ValueError("window must be > 0")
        self.capacity = capacity
        self.window = window
        self._state: Dict[str, Tuple[float, int]] = {}

    def record(self, peer_id: str, now: float) -> int:
        """Count one inbound message and return the count in this window."""
        window_start, count = self._state.get(peer_id, (now, 0))
        if now - window_start >= self.window:
            window_start, count = now, 0
        count += 1
        self._state[peer_id] = (window_start, count)
        return count

    def is_overactive(self, peer_id: str) -> bool:
        """Whether the last window already exceeded the allowance."""
        _start, count = self._state.get(peer_id, (0.0, 0))
        return count > self.capacity

    def reset(self, peer_id: str) -> None:
        self._state.pop(peer_id, None)


@dataclass(frozen=True)
class PeerBlock:
    """A recorded block of *peer_id* by the local node."""

    peer_id: str
    reason: str
    since: float
    until: float

    def to_dict(self) -> Dict[str, object]:
        return {
            "peer_id": self.peer_id,
            "reason": self.reason,
            "since": round(self.since, 9),
            "until": round(self.until, 9),
        }


class PeerBlockList:
    """Blocklist of peers for a *single* receiving node.

    ``node_id`` keeps log records unambiguous when several nodes block the
    same peer.
    """

    def __init__(self, node_id: str = "") -> None:
        self.node_id = node_id
        self._blocks: Dict[str, PeerBlock] = {}

    def block(self, peer_id: str, since: float, until: float, reason: str) -> PeerBlock:
        """Block (or extend the block of) *peer_id* until *until*."""
        entry = PeerBlock(peer_id=peer_id, reason=reason, since=since, until=until)
        self._blocks[peer_id] = entry
        return entry

    def unblock(self, peer_id: str) -> Optional[PeerBlock]:
        """Remove *peer_id* from the list; return the removed entry if any."""
        return self._blocks.pop(peer_id, None)

    def get(self, peer_id: str) -> Optional[PeerBlock]:
        return self._blocks.get(peer_id)

    def is_blocked(self, peer_id: str, now: float) -> bool:
        """Whether *peer_id* is blocked at time *now*.

        Expired entries are *not* removed here: the network layer removes them
        when the scheduled ``UNBLOCK`` event fires so the log always contains
        the matching ``UNBLOCK`` record of every ``BLOCK``.
        """
        entry = self._blocks.get(peer_id)
        return entry is not None and now < entry.until

    def blocked_peers(self, now: float) -> Tuple[str, ...]:
        return tuple(p for p in sorted(self._blocks) if self.is_blocked(p, now))

    def __len__(self) -> int:
        return len(self._blocks)
