"""Event-driven simulated network with fault injection.

Design goals
-----------
* **No threads, no sockets.**  A packet is an envelope plus a delivery
  timestamp; the :class:`~src.scheduler.Scheduler` advances simulated time.
  Consensus code therefore never blocks and a whole run is reproducible.
* **Partial synchrony.**  Before ``config.stabilize_at`` the network may drop,
  duplicate, delay and reorder packets.  From that instant on there are no
  drops and every packet arrives within ``config.max_delay`` (the Δ bound of
  Lab01 §3).  ``stabilize_at=None`` keeps the configured faults for the whole
  run, which is what the fault scenarios want.
* **Seeded and link-independent randomness.**  Every ``(sender, recipient)``
  link owns its own :class:`~src.network.rng.DeterministicRandom`, so the same
  seed reproduces the same faults even if unrelated parts of a scenario
  schedule different numbers of messages.
* **Header-before-body.**  A body is only transmitted to a peer that accepted
  the matching header, see :class:`~src.network.header_gate.HeaderGate`.
* **Complete event log.**  Every ``send``, ``deliver``, ``drop``, ``block``,
  ``unblock`` and ``header_accept`` is recorded with timestamp, node id,
  event type, message kind and height, as required by Lab01 §6.

Integration contract (used by ``src/node.py``)
----------------------------------------------
>>> net = Network(scheduler, NetworkConfig(num_nodes=8, seed=1), node_ids)
>>> net.set_receiver("node_1", lambda node_id, env: ...)   # envelope callback
>>> net.send("node_1", "node_2", message, kind="PREVOTE", height=3)
>>> scheduler.run()
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from src.scheduler import Scheduler
from src.network.header_gate import HeaderGate
from src.network.rate_limit import (
    InboundRateTracker,
    PeerBlock,
    PeerBlockList,
    RateLimitPolicy,
    TokenBucket,
)
from src.network.rng import DeterministicRandom


MIN_NODES: int = 8
"""Lab01 §6 requires the simulator to support at least 8 nodes."""

KIND_HEADER: str = "HEADER"
KIND_BODY_REQUEST: str = "BODY_REQUEST"
KIND_BODY: str = "BODY"


class NetworkEventType(str, Enum):
    """Types of network events written to the log."""

    SEND = "SEND"
    DELIVER = "DELIVER"
    DROP = "DROP"
    BLOCK = "BLOCK"
    UNBLOCK = "UNBLOCK"
    HEADER_ACCEPT = "HEADER_ACCEPT"


class SendStatus(str, Enum):
    """Outcome of a single :meth:`Network.send` call."""

    QUEUED = "QUEUED"
    SELF = "SELF"
    UNKNOWN_NODE = "UNKNOWN_NODE"
    BLOCKED = "BLOCKED"
    RATE_LIMITED = "RATE_LIMITED"
    HEADER_NOT_ACCEPTED = "HEADER_NOT_ACCEPTED"
    HEADER_NOT_SEEN = "HEADER_NOT_SEEN"
    MESSAGE_DROPPED = "MESSAGE_DROPPED"


class DropReason:
    """Stable drop-reason strings (also used by tests and the report)."""

    RANDOM = "random_drop"
    PEER_BLOCKED = "peer_blocked"
    RATE_LIMITED = "outbound_rate_limit"
    INBOUND_OVERACTIVE = "inbound_overactive"
    HEADER_NOT_ACCEPTED = "header_not_accepted"
    HEADER_NOT_SEEN = "header_not_seen"
    DUP_BODY = "duplicate_body"
    UNKNOWN_NODE = "unknown_node"


def _kind_str(kind: Any) -> str:
    """Normalise a message kind (``str``, ``str``-enum or other enum)."""
    if isinstance(kind, str):
        return kind
    value = getattr(kind, "value", None)
    return value if isinstance(value, str) else str(kind)


def _payload_height(payload: Any) -> Optional[int]:
    """Best-effort extraction of a consensus height for logging."""
    height = getattr(payload, "height", None)
    if isinstance(height, int):
        return height
    if isinstance(payload, dict):
        value = payload.get("height")
        if isinstance(value, int):
            return value
    return None


@dataclass(frozen=True)
class NetworkConfig:
    """Static network parameters; must be identical on every node of a run.

    Parameters
    ----------
    num_nodes : int
        Number of validators the scenario intends to run (Lab01 requires
        ``>= 8``).  Used by :meth:`validate` with ``strict=True``.
    seed : int
        Master seed for every random decision of the network layer.
    min_delay, max_delay : float
        Per-packet one-way delay is uniform in ``[min_delay, max_delay]``.
        ``max_delay`` doubles as the Δ synchrony bound.  ``max_delay >
        min_delay`` is what produces packet *reordering*: two packets sent in
        order get independent delays and may arrive swapped.
    drop_rate, duplicate_rate : float
        Independent per-packet loss and duplication probability.
    pre_synchrony_max_delay : float or None
        Upper delay bound used *before* ``stabilize_at``.  ``None`` means
        ``max_delay``; a larger value models a badly congested pre-synchrony
        network (T5).
    stabilize_at : float or None
        Simulated time from which the network is partially synchronous: no
        drops, no duplicates, delay ``<= max_delay``.  ``None`` disables the
        transition (faults apply for the whole run).
    rate_limit : RateLimitPolicy
        Outbound token bucket and inbound overactivity thresholds.
    enforce_header_gate : bool
        When ``True`` (default) bodies may only be sent to a peer that
        accepted the matching header.  Disable only for isolated unit tests.
    """

    num_nodes: int = MIN_NODES
    seed: int = 0
    min_delay: float = 0.01
    max_delay: float = 0.05
    drop_rate: float = 0.0
    duplicate_rate: float = 0.0
    pre_synchrony_max_delay: Optional[float] = None
    stabilize_at: Optional[float] = None
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    enforce_header_gate: bool = True

    def validate(self, strict: bool = False) -> List[str]:
        """Return configuration problems; empty list means valid.

        With ``strict=True`` the Lab01 requirement of ``num_nodes >= 8`` is
        enforced as well (kept out of the default path so small focused unit
        tests can use short topologies).
        """
        problems: List[str] = []
        if self.num_nodes < 1:
            problems.append("num_nodes must be >= 1")
        elif strict and self.num_nodes < MIN_NODES:
            problems.append(
                f"num_nodes must be >= {MIN_NODES} for a lab run (got {self.num_nodes})"
            )
        if self.min_delay < 0:
            problems.append("min_delay must be >= 0")
        if self.max_delay < self.min_delay:
            problems.append("max_delay must be >= min_delay")
        if self.pre_synchrony_max_delay is not None:
            if self.pre_synchrony_max_delay < self.min_delay:
                problems.append("pre_synchrony_max_delay must be >= min_delay")
        if not 0.0 <= self.drop_rate <= 1.0:
            problems.append("drop_rate must be in [0, 1]")
        if not 0.0 <= self.duplicate_rate <= 1.0:
            problems.append("duplicate_rate must be in [0, 1]")
        if self.stabilize_at is not None and self.stabilize_at < 0:
            problems.append("stabilize_at must be >= 0")
        problems.extend(self.rate_limit.validate())
        return problems

    def require_valid(self, strict: bool = False) -> "NetworkConfig":
        """Raise :class:`ValueError` if the configuration is invalid."""
        problems = self.validate(strict=strict)
        if problems:
            raise ValueError("invalid NetworkConfig: " + "; ".join(problems))
        return self

    # -- (de)serialisation for config/scenario files ----------------------

    def to_dict(self) -> Dict[str, Any]:
        """Plain dict, safe to dump as JSON/YAML."""
        return {
            "num_nodes": self.num_nodes,
            "seed": self.seed,
            "min_delay": self.min_delay,
            "max_delay": self.max_delay,
            "drop_rate": self.drop_rate,
            "duplicate_rate": self.duplicate_rate,
            "pre_synchrony_max_delay": self.pre_synchrony_max_delay,
            "stabilize_at": self.stabilize_at,
            "enforce_header_gate": self.enforce_header_gate,
            "rate_limit": {
                "capacity": self.rate_limit.capacity,
                "refill_per_second": self.rate_limit.refill_per_second,
                "inbound_capacity": self.rate_limit.inbound_capacity,
                "inbound_window": self.rate_limit.inbound_window,
                "peer_block_duration": self.rate_limit.peer_block_duration,
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkConfig":
        """Build a config from a scenario file (unknown keys are ignored)."""
        data = dict(data or {})
        rate_limit = data.pop("rate_limit", None)
        if isinstance(rate_limit, dict):
            data["rate_limit"] = RateLimitPolicy(**rate_limit)
        allowed = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in allowed})


@dataclass(frozen=True)
class NetworkEvent:
    """One entry of the network log (deterministic, JSON-ready)."""

    time: float
    event: str
    node_id: str
    peer_id: str = ""
    kind: str = ""
    height: Optional[int] = None
    envelope_id: str = ""
    header_id: str = ""
    delay: float = 0.0
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": round(self.time, 9),
            "event": self.event,
            "node_id": self.node_id,
            "peer_id": self.peer_id,
            "kind": self.kind,
            "height": self.height,
            "envelope_id": self.envelope_id,
            "header_id": self.header_id,
            "delay": round(self.delay, 9),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class NetworkEnvelope:
    """A packet in flight.

    ``payload`` is opaque to the network layer: the consensus ``Message``, a
    block header, a block body, …  ``header_id`` links bodies to the header
    they belong to and is required for every body message.
    """

    envelope_id: str
    kind: str
    sender_id: str
    recipient_id: str
    payload: Any
    send_time: float
    deliver_time: float
    header_id: str = ""
    height: Optional[int] = None
    is_duplicate: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "kind": self.kind,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "send_time": round(self.send_time, 9),
            "deliver_time": round(self.deliver_time, 9),
            "header_id": self.header_id,
            "height": self.height,
            "is_duplicate": self.is_duplicate,
        }


class Network:
    """Simulated unreliable network for a fixed set of validators."""

    def __init__(
        self,
        scheduler: Scheduler,
        config: Optional[NetworkConfig] = None,
        node_ids: Optional[Iterable[str]] = None,
        event_sink: Optional[Callable[[NetworkEvent], None]] = None,
    ) -> None:
        self.scheduler = scheduler
        self.config = (config or NetworkConfig()).require_valid()
        self._event_sink = event_sink

        if node_ids is None:
            node_ids = [f"node_{i + 1}" for i in range(self.config.num_nodes)]
        self._nodes: Tuple[str, ...] = tuple(node_ids)
        if not self._nodes:
            raise ValueError("network needs at least one node")
        if len(set(self._nodes)) != len(self._nodes):
            raise ValueError("node ids must be unique")

        self._receivers: Dict[str, Callable[[str, NetworkEnvelope], None]] = {}
        self._events: List[NetworkEvent] = []
        self._envelope_seq = 0

        seed = self.config.seed
        self._link_rngs: Dict[Tuple[str, str], DeterministicRandom] = {}
        self._seed = seed

        self._outbound: Dict[Tuple[str, str], TokenBucket] = {}
        self._inbound: Dict[Tuple[str, str], InboundRateTracker] = {}
        self._blocklists: Dict[str, PeerBlockList] = {n: PeerBlockList(n) for n in self._nodes}
        self._gate = HeaderGate()

        # counters are exposed for tests / reports
        self.counters: Dict[str, int] = {
            "sent": 0,
            "queued": 0,
            "delivered": 0,
            "dropped": 0,
            "rate_limited": 0,
            "blocked": 0,
            "header_rejected": 0,
            "duplicates_created": 0,
            "blocks": 0,
            "unblocks": 0,
        }

        for src in self._nodes:
            for dst in self._nodes:
                if src == dst:
                    continue
                self._link_rngs[(src, dst)] = DeterministicRandom(
                    seed, f"link:{src}->{dst}"
                )
                self._outbound[(src, dst)] = TokenBucket(
                    self.config.rate_limit.capacity,
                    self.config.rate_limit.refill_per_second,
                    start_time=scheduler.now,
                )
                self._inbound[(dst, src)] = InboundRateTracker(
                    self.config.rate_limit.inbound_capacity,
                    self.config.rate_limit.inbound_window,
                )

    # -- topology ---------------------------------------------------------

    @property
    def nodes(self) -> Tuple[str, ...]:
        return self._nodes

    @property
    def gate(self) -> HeaderGate:
        return self._gate

    def peers(self, node_id: str) -> Tuple[str, ...]:
        """Every other node (peers stay connected; blocking is soft)."""
        return tuple(n for n in self._nodes if n != node_id)

    def set_receiver(
        self, node_id: str, handler: Optional[Callable[[str, NetworkEnvelope], None]]
    ) -> None:
        """Register the callback invoked when *node_id* receives a packet."""
        if node_id not in self._nodes:
            raise KeyError(f"unknown node: {node_id}")
        if handler is None:
            self._receivers.pop(node_id, None)
        else:
            self._receivers[node_id] = handler

    def set_event_sink(self, sink: Optional[Callable[[NetworkEvent], None]]) -> None:
        """Attach a logger that receives every new event (TV5 logger)."""
        self._event_sink = sink

    # -- synchrony --------------------------------------------------------

    def is_synchronized(self) -> bool:
        """Whether the network has reached its post-stabilization phase."""
        moment = self.config.stabilize_at
        return moment is not None and self.scheduler.now >= moment

    def _effective_drop_rate(self) -> float:
        return 0.0 if self.is_synchronized() else self.config.drop_rate

    def _effective_duplicate_rate(self) -> float:
        return 0.0 if self.is_synchronized() else self.config.duplicate_rate

    def _sample_delay(self, rng: DeterministicRandom) -> float:
        hi = self.config.max_delay
        if not self.is_synchronized():
            chaotic = self.config.pre_synchrony_max_delay
            if chaotic is not None:
                hi = chaotic
        if hi <= 0:
            return 0.0
        low = min(self.config.min_delay, hi)
        return rng.uniform(low, hi)

    # -- events -----------------------------------------------------------

    @property
    def events(self) -> Tuple[NetworkEvent, ...]:
        return tuple(self._events)

    def drain_events(self) -> List[NetworkEvent]:
        """Return the buffered events and clear the buffer."""
        out, self._events = self._events, []
        return out

    def _log(
        self,
        event: NetworkEventType,
        node_id: str,
        peer_id: str = "",
        *,
        kind: str = "",
        height: Optional[int] = None,
        envelope_id: str = "",
        header_id: str = "",
        delay: float = 0.0,
        reason: str = "",
    ) -> NetworkEvent:
        record = NetworkEvent(
            time=self.scheduler.now,
            event=event.value,
            node_id=node_id,
            peer_id=peer_id,
            kind=kind,
            height=height,
            envelope_id=envelope_id,
            header_id=header_id,
            delay=delay,
            reason=reason,
        )
        self._events.append(record)
        if self._event_sink is not None:
            self._event_sink(record)
        return record

    def _next_envelope_id(self) -> str:
        self._envelope_seq += 1
        return f"env-{self._envelope_seq:07d}"

    # -- sending ----------------------------------------------------------

    def send(
        self,
        sender_id: str,
        recipient_id: str,
        payload: Any,
        *,
        kind: str = "MESSAGE",
        height: Optional[int] = None,
        header_id: Optional[str] = None,
    ) -> SendStatus:
        """Send one packet; returns the immediate outcome.

        The packet is *queued*, not delivered: it arrives when the scheduler
        reaches its delivery time.
        """
        kind_s = _kind_str(kind)
        if height is None:
            height = _payload_height(payload)
        return self._send_one(
            sender_id, recipient_id, payload, kind_s, height, header_id or ""
        )

    def broadcast(
        self,
        sender_id: str,
        payload: Any,
        *,
        kind: str = "MESSAGE",
        height: Optional[int] = None,
        header_id: Optional[str] = None,
        recipients: Optional[Sequence[str]] = None,
    ) -> Dict[str, SendStatus]:
        """Send to every peer (or to *recipients*); order is deterministic."""
        kind_s = _kind_str(kind)
        if height is None:
            height = _payload_height(payload)
        targets = tuple(recipients) if recipients is not None else self.peers(sender_id)
        results: Dict[str, SendStatus] = {}
        for dst in targets:
            results[dst] = self._send_one(
                sender_id, dst, payload, kind_s, height, header_id or ""
            )
        return results

    def _send_one(
        self,
        sender_id: str,
        recipient_id: str,
        payload: Any,
        kind: str,
        height: Optional[int],
        header_id: str,
    ) -> SendStatus:
        self.counters["sent"] += 1

        if sender_id == recipient_id:
            return SendStatus.SELF
        if sender_id not in self._nodes or recipient_id not in self._nodes:
            self.counters["dropped"] += 1
            self._log(
                NetworkEventType.DROP, sender_id, recipient_id,
                kind=kind, height=height, reason=DropReason.UNKNOWN_NODE,
            )
            return SendStatus.UNKNOWN_NODE

        envelope_id = self._next_envelope_id()

        # 1) header-before-body gate -------------------------------------
        if self.config.enforce_header_gate:
            if kind == KIND_BODY:
                if not header_id:
                    self.counters["header_rejected"] += 1
                    self._log(
                        NetworkEventType.DROP, sender_id, recipient_id, kind=kind,
                        height=height, envelope_id=envelope_id,
                        reason=DropReason.HEADER_NOT_ACCEPTED,
                    )
                    return SendStatus.HEADER_NOT_ACCEPTED
                if not self._gate.can_send_body(recipient_id, header_id):
                    self.counters["header_rejected"] += 1
                    self._log(
                        NetworkEventType.DROP, sender_id, recipient_id, kind=kind,
                        height=height, envelope_id=envelope_id, header_id=header_id,
                        reason=DropReason.HEADER_NOT_ACCEPTED,
                    )
                    return SendStatus.HEADER_NOT_ACCEPTED
            elif kind == KIND_BODY_REQUEST:
                if not header_id or not self._gate.has_header(sender_id, header_id):
                    self.counters["header_rejected"] += 1
                    self._log(
                        NetworkEventType.DROP, sender_id, recipient_id, kind=kind,
                        height=height, envelope_id=envelope_id, header_id=header_id,
                        reason=DropReason.HEADER_NOT_SEEN,
                    )
                    return SendStatus.HEADER_NOT_SEEN

        # 2) receiver already blocked the sender -------------------------
        if self.is_blocked(recipient_id, sender_id):
            self.counters["blocked"] += 1
            self.counters["dropped"] += 1
            self._log(
                NetworkEventType.DROP, sender_id, recipient_id, kind=kind,
                height=height, envelope_id=envelope_id,
                reason=DropReason.PEER_BLOCKED,
            )
            return SendStatus.BLOCKED

        # 3) outbound token bucket --------------------------------------
        bucket = self._outbound[(sender_id, recipient_id)]
        if not bucket.allow(self.scheduler.now):
            self.counters["rate_limited"] += 1
            self.counters["dropped"] += 1
            self._log(
                NetworkEventType.DROP, sender_id, recipient_id, kind=kind,
                height=height, envelope_id=envelope_id,
                reason=DropReason.RATE_LIMITED,
            )
            return SendStatus.RATE_LIMITED

        # 4) inbound overactivity -> temporary block --------------------
        tracker = self._inbound[(recipient_id, sender_id)]
        if tracker.record(sender_id, self.scheduler.now) > tracker.capacity:
            self.block_peer(
                recipient_id, sender_id,
                duration=self.config.rate_limit.peer_block_duration,
                reason=DropReason.INBOUND_OVERACTIVE,
            )
            self.counters["blocked"] += 1
            self.counters["dropped"] += 1
            self._log(
                NetworkEventType.DROP, sender_id, recipient_id, kind=kind,
                height=height, envelope_id=envelope_id,
                reason=DropReason.INBOUND_OVERACTIVE,
            )
            return SendStatus.BLOCKED

        # 5) random loss -------------------------------------------------
        rng = self._link_rngs[(sender_id, recipient_id)]
        if rng.chance(self._effective_drop_rate()):
            self.counters["dropped"] += 1
            self._log(
                NetworkEventType.DROP, sender_id, recipient_id, kind=kind,
                height=height, envelope_id=envelope_id,
                reason=DropReason.RANDOM,
            )
            return SendStatus.MESSAGE_DROPPED

        # 6) queue the packet, then possibly a duplicate -----------------
        self._enqueue(
            envelope_id, kind, sender_id, recipient_id, payload,
            header_id, height, self._sample_delay(rng), False,
        )
        if rng.chance(self._effective_duplicate_rate()):
            self.counters["duplicates_created"] += 1
            self._enqueue(
                self._next_envelope_id(), kind, sender_id, recipient_id, payload,
                header_id, height, self._sample_delay(rng), True,
            )
        return SendStatus.QUEUED

    def _enqueue(
        self,
        envelope_id: str,
        kind: str,
        sender_id: str,
        recipient_id: str,
        payload: Any,
        header_id: str,
        height: Optional[int],
        delay: float,
        is_duplicate: bool,
    ) -> NetworkEnvelope:
        envelope = NetworkEnvelope(
            envelope_id=envelope_id,
            kind=kind,
            sender_id=sender_id,
            recipient_id=recipient_id,
            payload=payload,
            send_time=self.scheduler.now,
            deliver_time=self.scheduler.now + delay,
            header_id=header_id,
            height=height,
            is_duplicate=is_duplicate,
        )
        self.counters["queued"] += 1
        self._log(
            NetworkEventType.SEND, sender_id, recipient_id, kind=kind,
            height=height, envelope_id=envelope_id, header_id=header_id,
            delay=delay, reason="duplicate" if is_duplicate else "",
        )
        self.scheduler.schedule_after(delay, self._deliver, envelope, tag="deliver")
        return envelope

    # -- header / body handshake -----------------------------------------

    def announce_header(
        self,
        sender_id: str,
        header_id: str,
        header_payload: Any,
        *,
        height: Optional[int] = None,
        recipients: Optional[Sequence[str]] = None,
    ) -> Dict[str, SendStatus]:
        """Broadcast a header; the proposer implicitly accepts its own header."""
        self._gate.announce(header_id, sender_id, owner_id=sender_id)
        self._gate.accept(sender_id, header_id)
        return self.broadcast(
            sender_id, header_payload, kind=KIND_HEADER,
            height=height, header_id=header_id, recipients=recipients,
        )

    def accept_header(self, node_id: str, header_id: str) -> bool:
        """Record that *node_id* wants the body referenced by *header_id*."""
        accepted = self._gate.accept(node_id, header_id)
        if accepted:
            self._log(
                NetworkEventType.HEADER_ACCEPT, node_id, self._gate.owner_of(header_id),
                kind=KIND_HEADER, header_id=header_id,
            )
        return accepted

    def request_body(
        self,
        node_id: str,
        peer_id: str,
        header_id: str,
        payload: Any = None,
        *,
        height: Optional[int] = None,
    ) -> SendStatus:
        """Ask *peer_id* for the body of an already-accepted header."""
        if payload is None:
            payload = {"header_id": header_id}
        return self.send(
            node_id, peer_id, payload, kind=KIND_BODY_REQUEST,
            height=height, header_id=header_id,
        )

    def send_body(
        self,
        sender_id: str,
        recipient_id: str,
        header_id: str,
        body_payload: Any,
        *,
        height: Optional[int] = None,
    ) -> SendStatus:
        """Send a body; rejected unless the recipient accepted the header."""
        return self.send(
            sender_id, recipient_id, body_payload, kind=KIND_BODY,
            height=height, header_id=header_id,
        )

    # -- delivering -------------------------------------------------------

    def _deliver(self, envelope: NetworkEnvelope) -> None:
        dst = envelope.recipient_id
        src = envelope.sender_id

        if self.is_blocked(dst, src):
            self.counters["blocked"] += 1
            self.counters["dropped"] += 1
            self._log(
                NetworkEventType.DROP, src, dst, kind=envelope.kind,
                height=envelope.height, envelope_id=envelope.envelope_id,
                header_id=envelope.header_id,
                reason=DropReason.PEER_BLOCKED,
            )
            return

        if envelope.kind == KIND_HEADER and envelope.header_id:
            self._gate.announce(envelope.header_id, dst, owner_id=src)

        reason = ""
        if envelope.kind == KIND_BODY:
            if self.config.enforce_header_gate and not self._gate.can_send_body(
                dst, envelope.header_id
            ):
                self.counters["header_rejected"] += 1
                self.counters["dropped"] += 1
                self._log(
                    NetworkEventType.DROP, src, dst, kind=envelope.kind,
                    height=envelope.height, envelope_id=envelope.envelope_id,
                    header_id=envelope.header_id,
                    reason=DropReason.HEADER_NOT_ACCEPTED,
                )
                return
            if not self._gate.mark_body_delivered(dst, envelope.header_id):
                reason = DropReason.DUP_BODY

        self.counters["delivered"] += 1
        self._log(
            NetworkEventType.DELIVER, src, dst, kind=envelope.kind,
            height=envelope.height, envelope_id=envelope.envelope_id,
            header_id=envelope.header_id, reason=reason,
        )

        handler = self._receivers.get(dst)
        if handler is not None:
            handler(dst, envelope)

    # -- peer blocking ----------------------------------------------------

    def block_peer(
        self,
        node_id: str,
        peer_id: str,
        *,
        duration: Optional[float] = None,
        reason: str = "manual",
    ) -> PeerBlock:
        """*node_id* blocks *peer_id* for *duration* seconds."""
        if node_id not in self._blocklists:
            raise KeyError(f"unknown node: {node_id}")
        length = (
            self.config.rate_limit.peer_block_duration if duration is None else duration
        )
        now = self.scheduler.now
        entry = self._blocklists[node_id].block(peer_id, now, now + length, reason)
        self.counters["blocks"] += 1
        self._log(
            NetworkEventType.BLOCK, node_id, peer_id, reason=reason, delay=length
        )
        if length > 0:
            self.scheduler.schedule_after(
                length, self._auto_unblock, node_id, peer_id, entry.until,
                tag="unblock",
            )
        else:
            self.unblock_peer(node_id, peer_id, reason="expired")
        return entry

    def _auto_unblock(self, node_id: str, peer_id: str, until: float) -> None:
        entry = self._blocklists[node_id].get(peer_id)
        if entry is None or entry.until != until:
            return  # already unblocked or extended by a newer block
        self.unblock_peer(node_id, peer_id, reason="expired")

    def unblock_peer(self, node_id: str, peer_id: str, reason: str = "manual") -> bool:
        """Remove *peer_id* from *node_id*'s blocklist."""
        if node_id not in self._blocklists:
            raise KeyError(f"unknown node: {node_id}")
        removed = self._blocklists[node_id].unblock(peer_id)
        if removed is None:
            return False
        self._inbound[(node_id, peer_id)].reset(peer_id)
        self.counters["unblocks"] += 1
        self._log(NetworkEventType.UNBLOCK, node_id, peer_id, reason=reason)
        return True

    def is_blocked(self, node_id: str, peer_id: str) -> bool:
        """Whether *node_id* currently blocks *peer_id*."""
        return self._blocklists[node_id].is_blocked(peer_id, self.scheduler.now)

    def blocked_peers(self, node_id: str) -> Tuple[str, ...]:
        return self._blocklists[node_id].blocked_peers(self.scheduler.now)
