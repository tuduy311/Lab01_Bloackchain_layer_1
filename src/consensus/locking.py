"""Locking and vote-signing guards for the BFT consensus state machine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from src.models import NIL_BLOCK_ID, Vote
from src.consensus.vote_pool import VotePool, VoteKey


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


# Compatibility alias: vote storage now lives in vote_pool.py as its own team
# responsibility, while older imports from locking.py continue to work.
VoteGuard = VotePool
