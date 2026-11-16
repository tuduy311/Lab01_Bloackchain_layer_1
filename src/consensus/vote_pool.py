"""Deterministic storage and deduplication for validator votes."""

from __future__ import annotations

from typing import Dict, Iterable, Optional, Set, Tuple

from src.models import Phase, Vote


VoteKey = Tuple[int, int, Phase, str]


class VotePool:
    """Store at most one vote per validator, height, round, and phase.

    A second vote for the same slot is ignored. If it targets another block,
    the pair is retained in :attr:`conflicts` so callers can report
    equivocation without counting the conflicting vote toward quorum.
    """

    def __init__(self, validators: Iterable[str]) -> None:
        self.validators: Set[str] = set(validators)
        self._votes: Dict[VoteKey, Vote] = {}
        self.conflicts: list[Tuple[Vote, Vote]] = []

    def add(self, vote: Vote) -> bool:
        """Store ``vote`` once; return ``False`` for duplicate or conflict."""
        if vote.voter_id not in self.validators:
            return False
        key = (vote.height, vote.round, vote.phase, vote.voter_id)
        previous = self._votes.get(key)
        if previous is not None:
            if previous.block_id != vote.block_id:
                conflict = (previous, vote)
                if conflict not in self.conflicts:
                    self.conflicts.append(conflict)
            return False
        self._votes[key] = vote
        return True

    def votes(
        self,
        height: int,
        round: int,
        phase: Phase,
        block_id: Optional[str] = None,
    ) -> Tuple[Vote, ...]:
        """Return matching votes ordered by validator ID."""
        values = (
            vote for key, vote in self._votes.items()
            if key[:3] == (height, round, phase)
            and (block_id is None or vote.block_id == block_id)
        )
        return tuple(sorted(values, key=lambda vote: vote.voter_id))

    def count(self, height: int, round: int, phase: Phase,
              block_id: str) -> int:
        return len(self.votes(height, round, phase, block_id))

    def has(self, height: int, round: int, phase: Phase,
            voter_id: str) -> bool:
        return (height, round, phase, voter_id) in self._votes

    def get(self, height: int, round: int, phase: Phase,
            voter_id: str) -> Optional[Vote]:
        return self._votes.get((height, round, phase, voter_id))

    def remove(self, vote: Vote) -> bool:
        """Remove a just-received vote that failed its attached proof check."""
        key = (vote.height, vote.round, vote.phase, vote.voter_id)
        if self._votes.get(key) != vote:
            return False
        del self._votes[key]
        return True

    def clear_before(self, height: int) -> None:
        """Discard stored votes from heights lower than ``height``."""
        self._votes = {
            key: vote for key, vote in self._votes.items() if key[0] >= height
        }


# The previous name remains available through locking.py for existing callers.
VoteGuard = VotePool
