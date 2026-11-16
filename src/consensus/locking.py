"""Locking and the VotePool API for the BFT consensus state machine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional, Set, Tuple

from src.models import NIL_BLOCK_ID, Phase, Vote


VoteKey = Tuple[int, int, Phase, str]
Slot = Tuple[int, int]


@dataclass(frozen=True)
class Polka:
    """A quorum of prevotes for one block and round."""

    height: int
    round: int
    block_id: str
    votes: Tuple[Vote, ...]


@dataclass
class LockState:
    """The lock and valid-round state for one consensus height."""

    locked_block_id: Optional[str] = None
    locked_round: Optional[int] = None
    valid_block_id: Optional[str] = None
    valid_round: Optional[int] = None

    def can_prevote(
        self,
        block_id: str,
        round: int,
        higher_round_polka: Optional[Polka] = None,
    ) -> bool:
        """Return whether the lock permits a prevote in ``round``.

        A lock can only be changed by a polka for another block in a strictly
        higher round.  A nil vote never unlocks a validator.
        """
        if self.locked_block_id is None:
            return True
        if block_id == self.locked_block_id:
            return True
        if block_id == NIL_BLOCK_ID or higher_round_polka is None:
            return False
        return (
            higher_round_polka.block_id == block_id
            and self.locked_round is not None
            and higher_round_polka.round > self.locked_round
        )

    def apply_polka(self, polka: Polka) -> bool:
        """Record a polka and lock its block when it is eligible.

        Returns ``True`` when the lock changed.  Nil polkas are ignored.
        """
        if polka.block_id == NIL_BLOCK_ID:
            return False
        if self.valid_round is None or polka.round >= self.valid_round:
            self.valid_block_id = polka.block_id
            self.valid_round = polka.round
        if self.locked_round is not None and polka.round <= self.locked_round:
            return False
        changed = (
            self.locked_block_id != polka.block_id
            or self.locked_round != polka.round
        )
        self.locked_block_id = polka.block_id
        self.locked_round = polka.round
        return changed

    def reset(self) -> None:
        self.locked_block_id = None
        self.locked_round = None
        self.valid_block_id = None
        self.valid_round = None


class VotePool:
    """Store one vote per validator/slot and query a deterministic quorum.

    Signature authentication belongs to the receiving node/consensus engine.
    The pool enforces membership and deduplication, including equivocation.
    """

    def __init__(self, validators: Iterable[str]) -> None:
        validators = tuple(validators)
        if not validators or len(set(validators)) != len(validators):
            raise ValueError("validators must be non-empty and unique")
        self.validators: Set[str] = set(validators)
        self.quorum = len(validators) - (len(validators) - 1) // 3
        self._votes: Dict[VoteKey, Vote] = {}
        self.conflicts: list[Tuple[Vote, Vote]] = []

    def add_vote(self, vote: Vote) -> bool:
        """Store ``vote`` once; return ``False`` for duplicate/conflict."""
        if vote.voter_id not in self.validators:
            return False
        key = (vote.height, vote.round, vote.phase, vote.voter_id)
        previous = self._votes.get(key)
        if previous is not None:
            if previous.block_id != vote.block_id:
                self.conflicts.append((previous, vote))
            return False
        self._votes[key] = vote
        return True

    def get_votes(
        self,
        height: int,
        round: int,
        phase: Phase,
        block_id: str,
    ) -> list[Vote]:
        """Return a fresh list for exactly one height/round/phase/block."""
        return [vote for vote in self.get_round_votes(height, round, phase)
                if vote.block_id == block_id]

    def has_quorum(
        self,
        height: int,
        round: int,
        phase: Phase,
        block_id: str,
    ) -> bool:
        return len(self.get_votes(height, round, phase, block_id)) >= self.quorum

    def get_round_votes(self, height: int, round: int, phase: Phase) -> list[Vote]:
        """All candidates in a slot, used for retransmission and engine polling."""
        return sorted((vote for key, vote in self._votes.items()
                       if key[:3] == (height, round, phase)), key=lambda vote: vote.voter_id)

    def has(self, height: int, round: int, phase: Phase, voter_id: str) -> bool:
        return (height, round, phase, voter_id) in self._votes

    def clear_before(self, height: int) -> None:
        self._votes = {
            key: vote for key, vote in self._votes.items() if key[0] >= height
        }
