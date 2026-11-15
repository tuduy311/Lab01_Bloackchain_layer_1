"""Data models for the Layer-1 blockchain simulator.

Provides canonical, hashable representations of Block, Transaction, Vote,
and the envelope Message type used on the P2P layer.

Design notes
------------
* Every model is a frozen dataclass so instances are immutable after creation.
* ``canonical_bytes()`` returns a deterministic byte string used for hashing
  and signature verification (JSON with sorted keys, UTF-8 encoded).
* ``block_id`` is always the SHA-256 hex digest of the block's canonical bytes
  (excluding the ``block_id`` field itself).
* ``state_root`` in Block is the SHA-256 of the world state **after** applying
  all transactions.  It is set by the execution engine and included in the
  canonical hash so two blocks with the same transactions but different
  pre-states get different ids.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Phase(Enum):
    """Consensus phases."""
    PROPOSAL = "PROPOSAL"
    PREVOTE = "PREVOTE"
    PRECOMMIT = "PRECOMMIT"
    FINALIZE = "FINALIZE"


class MessageType(Enum):
    """Types of messages exchanged between nodes."""
    PROPOSAL = "PROPOSAL"
    PREVOTE = "PREVOTE"
    PRECOMMIT = "PRECOMMIT"
    FINALIZE = "FINALIZE"


# ---------------------------------------------------------------------------
# Canonical encoding helper
# ---------------------------------------------------------------------------

def _canonical_json(obj: Any) -> bytes:
    """Return deterministic JSON bytes for *obj*.

    Keys are sorted, no extra whitespace, encoded as UTF-8.  This is the
    single source of truth for every ``canonical_bytes()`` implementation.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


# ---------------------------------------------------------------------------
# Transaction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Transaction:
    """A single state-transition instruction.

    Parameters
    ----------
    sender : str
        Public-key hex string of the sender.
    receiver : str
        Public-key hex string of the receiver.
    amount : int
        Non-negative integer amount to transfer.
    nonce : int
        Sender-scoped sequence number (anti-replay).
    signature : str
        Hex-encoded Ed25519 signature over the canonical payload
        ``(sender, receiver, amount, nonce)``.
    """
    sender: str
    receiver: str
    amount: int
    nonce: int
    signature: str = ""

    # -- canonical encoding (excludes signature) ----------------------------

    def payload_dict(self) -> Dict[str, Any]:
        """Return the dict that is signed / hashed (no signature field)."""
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "amount": self.amount,
            "nonce": self.nonce,
        }

    def canonical_bytes(self) -> bytes:
        """Canonical bytes of the *signable* payload (no signature)."""
        return _canonical_json(self.payload_dict())

    def to_dict(self) -> Dict[str, Any]:
        """Full dict including signature (for block serialisation)."""
        d = self.payload_dict()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Transaction":
        return cls(
            sender=d["sender"],
            receiver=d["receiver"],
            amount=int(d["amount"]),
            nonce=int(d["nonce"]),
            signature=d.get("signature", ""),
        )


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Block:
    """A proposed block in the chain.

    Parameters
    ----------
    height : int
        Chain height (0-indexed; genesis is height 0).
    round : int
        Consensus round in which this block was proposed.
    parent_id : str
        ``block_id`` of the parent block (empty string for genesis).
    transactions : tuple[Transaction, ...]
        Ordered tuple of transactions included in this block.
    proposer_id : str
        Identifier of the proposer validator.
    timestamp : float
        Simulation timestamp (seconds).
    block_id : str
        SHA-256 hex digest computed over the canonical content.  This field
        is **excluded** from the canonical representation itself.
    signature : str
        Proposer's Ed25519 signature over ``block_id``.
    """
    height: int
    round: int
    parent_id: str
    transactions: tuple = ()          # tuple[Transaction, ...]
    proposer_id: str = ""
    timestamp: float = 0.0
    state_root: str = ""   # SHA-256 of world state after executing this block's txs
    block_id: str = ""
    signature: str = ""

    # -- canonical encoding (excludes block_id and signature) ---------------

    def content_dict(self) -> Dict[str, Any]:
        """Content dict used to derive ``block_id`` (no id / sig)."""
        return {
            "height": self.height,
            "round": self.round,
            "parent_id": self.parent_id,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "proposer_id": self.proposer_id,
            "timestamp": self.timestamp,
            "state_root": self.state_root,
        }

    def canonical_bytes(self) -> bytes:
        """Canonical bytes **excluding** ``block_id`` and ``signature``."""
        return _canonical_json(self.content_dict())

    def to_dict(self) -> Dict[str, Any]:
        d = self.content_dict()
        d["block_id"] = self.block_id
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Block":
        txs = tuple(Transaction.from_dict(t) for t in d.get("transactions", []))
        return cls(
            height=int(d["height"]),
            round=int(d["round"]),
            parent_id=d["parent_id"],
            transactions=txs,
            proposer_id=d.get("proposer_id", ""),
            timestamp=float(d.get("timestamp", 0.0)),
            state_root=d.get("state_root", ""),
            block_id=d.get("block_id", ""),
            signature=d.get("signature", ""),
        )


# ---------------------------------------------------------------------------
# Vote
# ---------------------------------------------------------------------------

NIL_BLOCK_ID = "nil"
"""Sentinel value representing a nil vote (no block accepted)."""


@dataclass(frozen=True)
class Vote:
    """A single prevote or precommit cast by a validator.

    Parameters
    ----------
    height : int
        Consensus height this vote pertains to.
    round : int
        Consensus round.
    phase : Phase
        ``Phase.PREVOTE`` or ``Phase.PRECOMMIT``.
    block_id : str
        ``block_id`` of the voted block, or :data:`NIL_BLOCK_ID` for nil.
    voter_id : str
        Identifier (public key hex) of the voting validator.
    signature : str
        Ed25519 signature over the canonical vote payload.
    """
    height: int
    round: int
    phase: Phase
    block_id: str
    voter_id: str
    signature: str = ""

    @property
    def is_nil(self) -> bool:
        return self.block_id == NIL_BLOCK_ID

    # -- canonical encoding (excludes signature) ----------------------------

    def payload_dict(self) -> Dict[str, Any]:
        return {
            "height": self.height,
            "round": self.round,
            "phase": self.phase.value,
            "block_id": self.block_id,
            "voter_id": self.voter_id,
        }

    def canonical_bytes(self) -> bytes:
        """Canonical bytes of the signable payload (no signature)."""
        return _canonical_json(self.payload_dict())

    def to_dict(self) -> Dict[str, Any]:
        d = self.payload_dict()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Vote":
        return cls(
            height=int(d["height"]),
            round=int(d["round"]),
            phase=Phase(d["phase"]),
            block_id=d["block_id"],
            voter_id=d["voter_id"],
            signature=d.get("signature", ""),
        )


# ---------------------------------------------------------------------------
# FinalizeCertificate
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FinalizeCertificate:
    """Proof that a block was finalized (quorum of precommits).

    Parameters
    ----------
    height : int
        Height of the finalized block.
    round : int
        Round in which finalization occurred.
    block_id : str
        ``block_id`` of the finalized block.
    precommits : tuple[Vote, ...]
        The ``QUORUM`` precommit votes that justify finalization.
    """
    height: int
    round: int
    block_id: str
    precommits: tuple = ()  # tuple[Vote, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "height": self.height,
            "round": self.round,
            "block_id": self.block_id,
            "precommits": [v.to_dict() for v in self.precommits],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FinalizeCertificate":
        pcs = tuple(Vote.from_dict(v) for v in d.get("precommits", []))
        return cls(
            height=int(d["height"]),
            round=int(d["round"]),
            block_id=d["block_id"],
            precommits=pcs,
        )


# ---------------------------------------------------------------------------
# Message (network envelope)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Message:
    """Network-layer envelope wrapping a proposal, vote, or finalize notice.

    Parameters
    ----------
    msg_type : MessageType
        Discriminator for the payload.
    sender_id : str
        Node ID of the sender.
    height : int
        Consensus height (for fast filtering/routing).
    round : int
        Consensus round.
    payload : dict
        Serialised Block / Vote / FinalizeCertificate.
    """
    msg_type: MessageType
    sender_id: str
    height: int
    round: int
    payload: dict = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "msg_type": self.msg_type.value,
            "sender_id": self.sender_id,
            "height": self.height,
            "round": self.round,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Message":
        return cls(
            msg_type=MessageType(d["msg_type"]),
            sender_id=d["sender_id"],
            height=int(d["height"]),
            round=int(d["round"]),
            payload=d.get("payload", {}),
        )


# ---------------------------------------------------------------------------
# Genesis helpers
# ---------------------------------------------------------------------------

def genesis_block() -> Block:
    """Return the hard-coded genesis block (height 0, round 0, no txs).

    The ``block_id`` is the SHA-256 of the canonical content.  The block
    carries no signature (it is accepted unconditionally by all nodes).
    """
    from src.crypto import compute_block_id  # local import to avoid circular

    blk = Block(height=0, round=0, parent_id="")
    bid = compute_block_id(blk)
    return Block(
        height=blk.height,
        round=blk.round,
        parent_id=blk.parent_id,
        transactions=blk.transactions,
        proposer_id=blk.proposer_id,
        timestamp=blk.timestamp,
        state_root=blk.state_root,
        block_id=bid,
        signature="",
    )


# ---------------------------------------------------------------------------
# ValidatorSet — ordered, immutable set of validator public-key ids
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidatorSet:
    """An ordered, immutable set of validator identifiers.

    Parameters
    ----------
    validators : tuple[str, ...]
        Ordered tuple of validator ids (public-key hex strings or symbolic
        names for simulations).
    f : int
        Maximum number of Byzantine validators.  ``len(validators) >= 3*f+1``
        is enforced at construction.
    """
    validators: tuple       # tuple[str, ...]
    f: int = 0

    def __post_init__(self) -> None:
        vals = tuple(self.validators)
        if not vals:
            raise ValueError("ValidatorSet requires at least one validator")
        if len(set(vals)) != len(vals):
            raise ValueError("ValidatorSet: validator ids must be unique")
        f = self.f
        if f < 0:
            raise ValueError("f must be >= 0")
        if len(vals) < 3 * f + 1:
            raise ValueError(
                f"ValidatorSet: need n >= 3f+1, got n={len(vals)}, f={f}"
            )
        object.__setattr__(self, "validators", vals)

    @property
    def n(self) -> int:
        """Total number of validators."""
        return len(self.validators)

    @property
    def quorum(self) -> int:
        """Minimum vote count for a quorum: ``2f + 1``."""
        return 2 * self.f + 1

    def __contains__(self, validator_id: str) -> bool:
        return validator_id in self.validators

    def __len__(self) -> int:
        return len(self.validators)

    def __iter__(self):
        return iter(self.validators)

    @classmethod
    def from_public_keys(cls, public_keys: List[str], f: Optional[int] = None) -> "ValidatorSet":
        """Build from a list of Ed25519 public key hex strings.

        If *f* is omitted it is derived as ``(n - 1) // 3``.
        """
        n = len(public_keys)
        if f is None:
            f = (n - 1) // 3
        return cls(tuple(public_keys), f)

    def to_dict(self) -> Dict[str, Any]:
        return {"validators": list(self.validators), "f": self.f}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ValidatorSet":
        return cls(tuple(d["validators"]), int(d["f"]))


# ---------------------------------------------------------------------------
# Polka — a quorum of prevotes for one block / round
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Polka:
    """A quorum of prevotes witnessing that ``block_id`` received ``QUORUM``
    prevotes in ``(height, round)``.

    This model mirrors :class:`src.consensus.locking.Polka` but lives in
    *models* so it can be attached to network messages without circular
    imports between ``models`` ↔ ``consensus``.
    """
    height: int
    round: int
    block_id: str
    votes: tuple    # tuple[Vote, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "height": self.height,
            "round": self.round,
            "block_id": self.block_id,
            "votes": [v.to_dict() for v in self.votes],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Polka":
        return cls(
            height=int(d["height"]),
            round=int(d["round"]),
            block_id=d["block_id"],
            votes=tuple(Vote.from_dict(v) for v in d.get("votes", [])),
        )
