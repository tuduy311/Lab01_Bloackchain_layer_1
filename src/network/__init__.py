"""Simulated P2P network layer (TV3).

Public surface used by the node / simulator:

* :class:`Network` – event-driven, seeded, unreliable transport.
* :class:`NetworkConfig` – delay / drop / duplicate / synchrony / rate-limit
  parameters, identical on every node of a run.
* :class:`NetworkEnvelope` – a packet in flight, handed to the receiver
  callback registered with :meth:`Network.set_receiver`.
* :class:`NetworkEvent` / :class:`NetworkEventType` – the deterministic log
  records consumed by the logger (TV5).
* :class:`SendStatus` / :class:`DropReason` – machine-readable outcomes.
* :class:`HeaderGate` – header-before-body propagation guard.
* :class:`RateLimitPolicy`, :class:`TokenBucket`, :class:`PeerBlockList` –
  outbound rate limiting and temporary peer blocking.
* :func:`DeterministicRandom`, :func:`derive_seed` – seeded randomness.
"""

from src.network.header_gate import HeaderGate
from src.network.network import (
    KIND_BODY,
    KIND_BODY_REQUEST,
    KIND_HEADER,
    MIN_NODES,
    DropReason,
    Network,
    NetworkConfig,
    NetworkEnvelope,
    NetworkEvent,
    NetworkEventType,
    SendStatus,
)
from src.network.rate_limit import (
    InboundRateTracker,
    PeerBlock,
    PeerBlockList,
    RateLimitPolicy,
    TokenBucket,
)
from src.network.rng import DeterministicRandom, derive_seed, hash_to_unit

__all__ = [
    "DropReason",
    "DeterministicRandom",
    "HeaderGate",
    "InboundRateTracker",
    "KIND_BODY",
    "KIND_BODY_REQUEST",
    "KIND_HEADER",
    "MIN_NODES",
    "Network",
    "NetworkConfig",
    "NetworkEnvelope",
    "NetworkEvent",
    "NetworkEventType",
    "PeerBlock",
    "PeerBlockList",
    "RateLimitPolicy",
    "SendStatus",
    "TokenBucket",
    "derive_seed",
    "hash_to_unit",
]