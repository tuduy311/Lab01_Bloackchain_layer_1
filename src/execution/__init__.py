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

Block validation rules (checked by :meth:`BlockValidator.validate`)
-----------------------------------------------------------
1. ``block_id`` must match SHA-256 of the canonical content.
2. If a public key or resolver is configured, the proposer's Ed25519 signature
   must be valid.
3. ``parent_id`` and height must match the caller-supplied parent Block.
4. All transactions must pass :func:`validate_transaction` sequentially
   (using the running state so nonces and balances are updated in order).
5. With ``require_state_root=True``, the block must carry the hash of the
   resulting world state. The committed pre-state must match the parent's
   root when that parent carries one.

Determinism guarantee
---------------------
Given the same ``pre_state`` and the same ordered list of transactions,
:func:`execute_block` always produces the same ``post_state`` and the same
``state_root``.  The ``state_root`` is the SHA-256 hex digest of the
canonical JSON representation of the full state (accounts sorted by
address).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple, Union

from src.crypto import (
    sha256_hex,
    verify_transaction_signature,
    verify_block_id,
    verify_block_signature,
)
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
# Block validation (pre-vote check)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BlockValidationResult:
    """Outcome of a full block validation."""
    valid: bool
    error: str = ""
    state_root: str = ""       # post-execution state root (only when valid)


class BlockValidator:
    """Validate a block against its parent with ``validate(block, parent) -> bool``.

    The pre-state is constructor context, either a WorldState or a callable
    returning the current committed state. Nodes use a callable because commit
    replaces their WorldState object. Diagnostic details are in ``last_result``.
    This class owns the validation logic; there is no legacy function adapter.
    """

    def __init__(
        self, pre_state: Union[WorldState, Callable[[], WorldState]], *,
        proposer_public_key: Optional[str] = None,
        public_key_resolver: Optional[Callable[[str], str]] = None,
        proposer_resolver: Optional[Callable[[int, int], str]] = None,
        require_state_root: bool = False,
    ) -> None:
        if not isinstance(pre_state, WorldState) and not callable(pre_state):
            raise TypeError("pre_state must be a WorldState or state provider")
        if proposer_public_key is not None and public_key_resolver is not None:
            raise ValueError("provide a fixed public key or a key resolver, not both")
        self._state_provider = pre_state if callable(pre_state) else lambda: pre_state
        self.proposer_public_key = proposer_public_key
        self.public_key_resolver = public_key_resolver
        self.proposer_resolver = proposer_resolver
        self.require_state_root = require_state_root
        self.last_result = BlockValidationResult(False, "no block validated")

    def _reject(self, error: str) -> bool:
        self.last_result = BlockValidationResult(False, error)
        return False

    def validate(self, block: Block, parent: Block) -> bool:
        """Check linkage, hash, authentication, execution and root without committing."""
        if not isinstance(block, Block) or not isinstance(parent, Block):
            return self._reject("block and parent must be Block instances")
        if block.height != parent.height + 1 or block.round < 0:
            return self._reject("invalid block height or round relative to parent")
        if not verify_block_id(block):
            return self._reject("block_id does not match canonical content")
        if block.parent_id != parent.block_id:
            return self._reject(
                f"parent_id mismatch: expected {parent.block_id!r}, got {block.parent_id!r}"
            )
        if self.proposer_resolver is not None and (
            self.proposer_resolver(block.height, block.round) != block.proposer_id
        ):
            return self._reject("wrong original proposer")
        public_key = self.proposer_public_key
        if self.public_key_resolver is not None:
            try:
                public_key = self.public_key_resolver(block.proposer_id)
            except KeyError:
                return self._reject("unknown proposer")
        if public_key is not None and not verify_block_signature(block, public_key):
            return self._reject("invalid proposer signature")
        pre_state = self._state_provider()
        if not isinstance(pre_state, WorldState):
            return self._reject("state provider did not return a WorldState")
        if parent.state_root and parent.state_root != pre_state.state_root():
            return self._reject("pre-state does not match parent state_root")
        work_state = pre_state.copy()
        for i, tx in enumerate(block.transactions):
            result = apply_transaction(tx, work_state)
            if not result.success:
                return self._reject(f"tx[{i}] invalid: {result.error}")
        computed_root = work_state.state_root()
        if self.require_state_root:
            if not block.state_root:
                return self._reject("missing state_root")
            if block.state_root != computed_root:
                return self._reject(
                    f"state_root mismatch: block has {block.state_root!r}, computed {computed_root!r}"
                )
        self.last_result = BlockValidationResult(True, state_root=computed_root)
        return True


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
