"""Deterministic transaction execution engine.

This module implements a simple account-based state model and a
deterministic execution engine that applies transactions to that state.

State model
-----------
* The state is a mapping from **account address** (public-key hex) to an
  :class:`AccountState` holding ``balance`` and ``nonce``.
* New accounts are implicitly created with balance 0 and nonce 0 when they
  first appear as a receiver.
* A transfer debits the sender and credits the receiver atomically.

Execution rules
---------------
1. The sender must exist and have ``balance >= amount``.
2. ``amount`` must be ≥ 0.
3. The transaction ``nonce`` must equal the sender's current ``nonce``
   (strict ordering, no gaps).
4. The sender's Ed25519 signature over the canonical transaction payload
   must be valid.
5. If any rule is violated the transaction is **rejected** (not applied).
   The block itself is considered invalid if it contains a rejected
   transaction, so the consensus layer must validate the block before
   voting.

Determinism guarantee
---------------------
Given the same ``pre_state`` and the same ordered list of transactions,
:func:`execute_block` always produces the same ``post_state`` and the same
``state_root``.  The ``state_root`` is the SHA-256 hex digest of the
canonical JSON representation of the full state (accounts sorted by
address).
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from src.crypto import sha256_hex, verify_transaction_signature
from src.models import Transaction, Block, _canonical_json


# ---------------------------------------------------------------------------
# Account state
# ---------------------------------------------------------------------------

@dataclass
class AccountState:
    """Mutable per-account state."""
    balance: int = 0
    nonce: int = 0

    def to_dict(self) -> dict:
        return {"balance": self.balance, "nonce": self.nonce}

    @classmethod
    def from_dict(cls, d: dict) -> "AccountState":
        return cls(balance=int(d["balance"]), nonce=int(d["nonce"]))


# ---------------------------------------------------------------------------
# World state
# ---------------------------------------------------------------------------

@dataclass
class WorldState:
    """Mapping of addresses to account states.

    Provides deep-copy semantics so that speculative execution during
    proposal validation does not mutate the committed state.
    """
    accounts: Dict[str, AccountState] = field(default_factory=dict)

    # -- query --------------------------------------------------------------

    def get_account(self, address: str) -> AccountState:
        """Return account for *address*, creating it lazily if absent."""
        if address not in self.accounts:
            self.accounts[address] = AccountState()
        return self.accounts[address]

    def get_balance(self, address: str) -> int:
        return self.get_account(address).balance

    def get_nonce(self, address: str) -> int:
        return self.get_account(address).nonce

    # -- mutation -----------------------------------------------------------

    def set_balance(self, address: str, balance: int) -> None:
        self.get_account(address).balance = balance

    def credit(self, address: str, amount: int) -> None:
        self.get_account(address).balance += amount

    def debit(self, address: str, amount: int) -> None:
        self.get_account(address).balance -= amount

    def increment_nonce(self, address: str) -> None:
        self.get_account(address).nonce += 1

    # -- copy / hash --------------------------------------------------------

    def copy(self) -> "WorldState":
        """Return a deep copy of the state."""
        return WorldState(
            accounts={addr: AccountState(a.balance, a.nonce)
                      for addr, a in self.accounts.items()}
        )

    def state_root(self) -> str:
        """Compute a deterministic hash of the entire state.

        The state is serialised as ``{"accounts": {addr: {balance, nonce}, ...}}``
        with addresses sorted lexicographically.
        """
        ordered = {addr: self.accounts[addr].to_dict()
                   for addr in sorted(self.accounts)}
        return sha256_hex(_canonical_json({"accounts": ordered}))

    def to_dict(self) -> dict:
        return {
            "accounts": {addr: acc.to_dict()
                         for addr, acc in sorted(self.accounts.items())}
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WorldState":
        accs = {addr: AccountState.from_dict(a)
                for addr, a in d.get("accounts", {}).items()}
        return cls(accounts=accs)


# ---------------------------------------------------------------------------
# Transaction validation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TxResult:
    """Outcome of a single transaction execution attempt."""
    success: bool
    error: str = ""


def validate_transaction(tx: Transaction, state: WorldState) -> TxResult:
    """Validate *tx* against *state* **without** mutating the state.

    Returns a :class:`TxResult` indicating success or the reason for
    rejection.
    """
    # 1. Amount must be non-negative
    if tx.amount < 0:
        return TxResult(False, f"negative amount: {tx.amount}")

    # 2. Sender must exist and have sufficient balance
    sender_acc = state.get_account(tx.sender)
    if sender_acc.balance < tx.amount:
        return TxResult(False,
                        f"insufficient balance: have {sender_acc.balance}, "
                        f"need {tx.amount}")

    # 3. Nonce must match
    if tx.nonce != sender_acc.nonce:
        return TxResult(False,
                        f"nonce mismatch: expected {sender_acc.nonce}, "
                        f"got {tx.nonce}")

    # 4. Signature must be valid
    if not verify_transaction_signature(tx):
        return TxResult(False, "invalid signature")

    return TxResult(True)


def apply_transaction(tx: Transaction, state: WorldState) -> TxResult:
    """Validate and apply *tx*, mutating *state* in place on success.

    Returns a :class:`TxResult`.
    """
    result = validate_transaction(tx, state)
    if not result.success:
        return result

    # Debit sender, credit receiver, bump nonce
    state.debit(tx.sender, tx.amount)
    state.credit(tx.receiver, tx.amount)
    state.increment_nonce(tx.sender)
    return TxResult(True)


# ---------------------------------------------------------------------------
# Block execution
# ---------------------------------------------------------------------------

def execute_block(
    block: Block,
    pre_state: WorldState,
    *,
    dry_run: bool = False,
) -> Tuple[bool, WorldState, str, List[TxResult]]:
    """Execute all transactions in *block* against *pre_state*.

    Parameters
    ----------
    block : Block
        The block whose transactions are to be executed.
    pre_state : WorldState
        The world state **before** this block.  Not mutated.
    dry_run : bool
        If ``True``, run validation on a copy and return the resulting
        state without committing.  Useful during proposal verification.

    Returns
    -------
    (valid, post_state, state_root, results)
        * ``valid`` – ``True`` iff every transaction succeeded.
        * ``post_state`` – the state after execution (a copy of
          ``pre_state`` if any tx failed and ``dry_run`` is ``True``).
        * ``state_root`` – SHA-256 hex digest of ``post_state``.
        * ``results`` – per-transaction :class:`TxResult` list.
    """
    work_state = pre_state.copy()
    results: List[TxResult] = []
    all_valid = True

    for tx in block.transactions:
        res = apply_transaction(tx, work_state)
        results.append(res)
        if not res.success:
            all_valid = False
            break  # first invalid tx makes the block invalid

    if not all_valid and dry_run:
        # Return original state untouched
        return False, pre_state.copy(), pre_state.state_root(), results

    post_state = work_state
    return all_valid, post_state, post_state.state_root(), results


# ---------------------------------------------------------------------------
# Convenience: initialise genesis state
# ---------------------------------------------------------------------------

def create_genesis_state(
    initial_balances: Dict[str, int],
) -> WorldState:
    """Create a :class:`WorldState` pre-funded with *initial_balances*.

    Parameters
    ----------
    initial_balances : dict[str, int]
        Mapping of address (public-key hex) to starting balance.

    Returns
    -------
    WorldState
    """
    state = WorldState()
    for addr, bal in initial_balances.items():
        state.set_balance(addr, bal)
    return state
