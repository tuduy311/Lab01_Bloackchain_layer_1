"""Header-before-body propagation guard.

Lab01 §6: *"Headers are broadcast before bodies; a body may be sent only after
the receiver accepts the matching header."*  This is the network-level analogue
of Ethereum's ``NewBlockHashes`` → ``GetBlockBodies`` handshake and it is what
prevents a body flood: a node must advertise a header, the receiver decides
whether it wants the payload, and only then may the body travel.

The gate is deliberately dumb state plus pure predicates so it can be unit
tested and logged independently of the rest of the network::

    header broadcast : gate.announce(header_id, receiver)
    receiver decides : gate.accept(receiver, header_id)      # False if unseen
    body may travel  : gate.can_send_body(receiver, header_id)
    body delivered   : gate.mark_body_delivered(receiver, header_id)

Each body is delivered at most once per receiver; duplicates stay dropped at
the gate even if the underlying network duplicates the packet.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple


class HeaderGate:
    """Tracks which headers each node has seen and accepted."""

    def __init__(self) -> None:
        # header_id -> set of node ids that received the header announcement
        self._announced: Dict[str, Set[str]] = {}
        # (node_id, header_id) pairs whose body may be transferred / was sent
        self._accepted: Set[Tuple[str, str]] = set()
        # (node_id, header_id) pairs whose body has already been delivered
        self._delivered: Set[Tuple[str, str]] = set()
        # header_id -> owner (proposer) node id, useful for log correlation
        self._owners: Dict[str, str] = {}

    # -- header phase -----------------------------------------------------

    def announce(self, header_id: str, node_id: str, owner_id: str = "") -> None:
        """Record that *node_id* received the header *header_id*."""
        if not header_id:
            raise ValueError("header_id must not be empty")
        self._announced.setdefault(header_id, set()).add(node_id)
        if owner_id:
            self._owners[header_id] = owner_id

    def has_header(self, node_id: str, header_id: str) -> bool:
        """Whether *node_id* has received the header announcement."""
        return node_id in self._announced.get(header_id, ())

    def accept(self, node_id: str, header_id: str) -> bool:
        """Accept the header on behalf of *node_id*.

        Returns ``False`` when the node never saw the header (or the header is
        unknown), in which case the network layer logs a rejection.
        """
        if not self.has_header(node_id, header_id):
            return False
        self._accepted.add((node_id, header_id))
        return True

    def is_accepted(self, node_id: str, header_id: str) -> bool:
        return (node_id, header_id) in self._accepted

    def accepted_headers(self, node_id: str) -> List[str]:
        """Headers accepted by *node_id*, in deterministic (sorted) order."""
        return sorted(h for (n, h) in self._accepted if n == node_id)

    # -- body phase -------------------------------------------------------

    def can_send_body(self, node_id: str, header_id: str) -> bool:
        """Bodies may travel only to a receiver that accepted the header."""
        return (node_id, header_id) in self._accepted

    def mark_body_delivered(self, node_id: str, header_id: str) -> bool:
        """Mark a body as delivered; return ``False`` if it was a duplicate."""
        key = (node_id, header_id)
        if key in self._delivered:
            return False
        self._delivered.add(key)
        return True

    def is_body_delivered(self, node_id: str, header_id: str) -> bool:
        return (node_id, header_id) in self._delivered

    # -- introspection ----------------------------------------------------

    def owner_of(self, header_id: str) -> str:
        return self._owners.get(header_id, "")

    def status(self, node_id: str, header_id: str) -> str:
        """Human/log friendly state of one (node, header) pair."""
        if self.is_body_delivered(node_id, header_id):
            return "BODY_DELIVERED"
        if self.is_accepted(node_id, header_id):
            return "ACCEPTED"
        if self.has_header(node_id, header_id):
            return "ANNOUNCED"
        return "UNKNOWN"

    def __len__(self) -> int:
        return len(self._delivered)

    def reset(self) -> None:
        self._announced.clear()
        self._accepted.clear()
        self._delivered.clear()
        self._owners.clear()
