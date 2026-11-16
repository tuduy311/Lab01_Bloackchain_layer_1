"""Cryptographic utilities: hashing, signing, and verification.

This module provides:

* SHA-256 hashing via :func:`sha256_hex`.
* Ed25519 key generation, signing, and verification using the Python
  standard-library ``hashlib`` + ``hmac`` for hashing and the
  ``cryptography`` package (``Ed25519PrivateKey`` / ``Ed25519PublicKey``)
  for digital signatures.
* Deterministic ``block_id`` computation from a :class:`Block`'s canonical
  bytes.
* Convenience wrappers for signing and verifying Votes, Transactions,
  and Blocks.

All public-key and signature representations are **hex-encoded strings**
for easy JSON serialisation.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[str, str]:
    """Generate an Ed25519 keypair.

    Returns
    -------
    (private_key_hex, public_key_hex)
        Both are hex-encoded raw key bytes (32 bytes each → 64 hex chars).
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return private_bytes.hex(), public_bytes.hex()


def _private_key_from_hex(hex_str: str) -> Ed25519PrivateKey:
    """Reconstruct an ``Ed25519PrivateKey`` from raw hex bytes."""
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))


def _public_key_from_hex(hex_str: str) -> Ed25519PublicKey:
    """Reconstruct an ``Ed25519PublicKey`` from raw hex bytes."""
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def public_key_from_private(private_hex: str) -> str:
    """Derive the public-key hex from a private-key hex."""
    pk = _private_key_from_hex(private_hex)
    return pk.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


# ---------------------------------------------------------------------------
# Sign / verify raw bytes
# ---------------------------------------------------------------------------

def sign(data: bytes, private_key_hex: str) -> str:
    """Sign *data* with the Ed25519 private key and return hex signature."""
    pk = _private_key_from_hex(private_key_hex)
    sig = pk.sign(data)
    return sig.hex()


def verify(data: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """Verify an Ed25519 signature.  Returns ``True`` iff valid."""
    try:
        pub = _public_key_from_hex(public_key_hex)
        pub.verify(bytes.fromhex(signature_hex), data)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# Block-id computation
# ---------------------------------------------------------------------------

def compute_block_id(block) -> str:
    """Compute ``block_id`` = SHA-256 hex of a Block's canonical bytes.

    Parameters
    ----------
    block : src.models.Block
        A Block instance.  Only ``content_dict()`` is used, so ``block_id``
        and ``signature`` are excluded.
    """
    return sha256_hex(block.canonical_bytes())


# ---------------------------------------------------------------------------
# Block helpers
# ---------------------------------------------------------------------------

def sign_block(block, private_key_hex: str):
    """Return a new Block with computed ``block_id`` and ``signature``.

    Parameters
    ----------
    block : src.models.Block
        Block template (``block_id`` and ``signature`` will be overwritten).
    private_key_hex : str
        Proposer's private key.

    Returns
    -------
    src.models.Block
        A new frozen Block with ``block_id`` and ``signature`` filled in.
    """
    from src.models import Block  # local to avoid circular import

    bid = compute_block_id(block)
    sig = sign(bid.encode("utf-8"), private_key_hex)
    return Block(
        height=block.height,
        round=block.round,
        parent_id=block.parent_id,
        transactions=block.transactions,
        proposer_id=block.proposer_id,
        timestamp=block.timestamp,
        state_root=block.state_root,
        block_id=bid,
        signature=sig,
    )


def verify_block_signature(block, public_key_hex: str) -> bool:
    """Check the proposer's signature over ``block_id``."""
    if not block.block_id or not block.signature:
        return False
    return verify(block.block_id.encode("utf-8"),
                  block.signature, public_key_hex)


def verify_block_id(block) -> bool:
    """Check that ``block.block_id`` matches the canonical content hash."""
    return compute_block_id(block) == block.block_id


# ---------------------------------------------------------------------------
# Vote helpers
# ---------------------------------------------------------------------------

def sign_vote(vote, private_key_hex: str):
    """Return a new Vote with a valid ``signature``.

    Parameters
    ----------
    vote : src.models.Vote
        Vote template.
    private_key_hex : str
        Voter's private key.

    Returns
    -------
    src.models.Vote
    """
    from src.models import Vote  # local import

    sig = sign(vote.canonical_bytes(), private_key_hex)
    return Vote(
        height=vote.height,
        round=vote.round,
        phase=vote.phase,
        block_id=vote.block_id,
        voter_id=vote.voter_id,
        signature=sig,
    )


def verify_vote_signature(vote, public_key_hex: str) -> bool:
    """Verify the signature of a vote against the voter's public key."""
    if not vote.signature:
        return False
    return verify(vote.canonical_bytes(), vote.signature, public_key_hex)


# ---------------------------------------------------------------------------
# Transaction helpers
# ---------------------------------------------------------------------------

def sign_transaction(tx, private_key_hex: str):
    """Return a new Transaction with a valid ``signature``.

    Parameters
    ----------
    tx : src.models.Transaction
        Transaction template.
    private_key_hex : str
        Sender's private key.

    Returns
    -------
    src.models.Transaction
    """
    from src.models import Transaction

    sig = sign(tx.canonical_bytes(), private_key_hex)
    return Transaction(
        sender=tx.sender,
        receiver=tx.receiver,
        amount=tx.amount,
        nonce=tx.nonce,
        signature=sig,
    )


def verify_transaction_signature(tx) -> bool:
    """Verify a transaction's signature using the sender's public key.

    The sender field **is** the public key hex, so we verify against it.
    """
    if not tx.signature or not tx.sender:
        return False
    return verify(tx.canonical_bytes(), tx.signature, tx.sender)


# ---------------------------------------------------------------------------
# ValidatorKeyStore — manage Ed25519 keypairs for a validator set
# ---------------------------------------------------------------------------

class ValidatorKeyStore:
    """Manages Ed25519 keypairs for a set of validators.

    Useful for deterministic simulation: generate all validator keys from a
    single seed so every run with the same seed uses the same keys.

    Parameters
    ----------
    validator_ids : list[str]
        Logical names for the validators (e.g. ``"v1"``, ``"v2"``…).  These
        are the symbolic ids used in consensus; the *public key* is stored
        separately and used for signature verification.

    Usage
    -----
    >>> store = ValidatorKeyStore(["v1", "v2", "v3", "v4"])
    >>> priv = store.private_key("v1")
    >>> pub  = store.public_key("v1")
    >>> vote = Vote(1, 0, Phase.PREVOTE, "bid", "v1")
    >>> signed = sign_vote(vote, priv)
    >>> verify_vote_signature(signed, pub)
    True
    """

    def __init__(self, validator_ids: List[str], seed: Optional[int] = None) -> None:
        if not validator_ids:
            raise ValueError("ValidatorKeyStore: need at least one validator")
        if len(set(validator_ids)) != len(validator_ids):
            raise ValueError("ValidatorKeyStore: validator ids must be unique")
        self._ids: Tuple[str, ...] = tuple(validator_ids)
        self._private: Dict[str, str] = {}
        self._public: Dict[str, str] = {}
        for vid in validator_ids:
            if seed is None:
                priv, pub = generate_keypair()
            else:
                # Reproducible simulator keys, NOT secret production keys.
                priv = sha256_hex(f"lab01:validator:{seed}:{vid}".encode("utf-8"))
                pub = public_key_from_private(priv)
            self._private[vid] = priv
            self._public[vid] = pub

    # -- query --------------------------------------------------------------

    @property
    def validator_ids(self) -> Tuple[str, ...]:
        return self._ids

    @property
    def public_keys(self) -> Tuple[str, ...]:
        """Public keys in the same order as :attr:`validator_ids`."""
        return tuple(self._public[vid] for vid in self._ids)

    def private_key(self, validator_id: str) -> str:
        """Return the private key hex for *validator_id*."""
        try:
            return self._private[validator_id]
        except KeyError:
            raise KeyError(f"unknown validator: {validator_id!r}") from None

    def public_key(self, validator_id: str) -> str:
        """Return the public key hex for *validator_id*."""
        try:
            return self._public[validator_id]
        except KeyError:
            raise KeyError(f"unknown validator: {validator_id!r}") from None

    def __contains__(self, validator_id: str) -> bool:
        return validator_id in self._private

    def __len__(self) -> int:
        return len(self._ids)

    # -- signing helpers ----------------------------------------------------

    def sign_vote_as(self, vote, validator_id: str):
        """Return a signed Vote for *validator_id*."""
        return sign_vote(vote, self.private_key(validator_id))

    def sign_block_as(self, block, validator_id: str):
        """Return a signed Block proposed by *validator_id*."""
        return sign_block(block, self.private_key(validator_id))

    def sign_transaction_as(self, tx, validator_id: str):
        """Return a signed Transaction sent by *validator_id*."""
        return sign_transaction(tx, self.private_key(validator_id))

    def verify_vote(self, vote, validator_id: str) -> bool:
        """Verify that the vote's signature belongs to *validator_id*."""
        return verify_vote_signature(vote, self.public_key(validator_id))

    def verify_block(self, block, validator_id: str) -> bool:
        """Verify that the block's signature belongs to *validator_id*."""
        return verify_block_signature(block, self.public_key(validator_id))
