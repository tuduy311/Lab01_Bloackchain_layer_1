"""Deterministic proposer (leader) selection.

Every node must agree, without communicating, on who may propose at
``(height, round)``.  If two nodes disagreed, two blocks could be proposed for
the same slot and liveness would depend on luck; if the rule depended on local
state (arrival order, clocks) the run would not be reproducible.

Selection rule
--------------
1. The fixed validator set is permuted **once** with a seed-derived
   Fisher-Yates shuffle (:attr:`ProposerSelector.engine_order`).  The
   permutation only depends on ``(validators, seed)``, so all nodes compute the
   same order and a scenario seed controls the leader ring.
2. The proposer of ``(height, round)`` is
   ``engine_order[(height + round) % n]``.

Rule 2 rotates the leader on every round *within* a height and cycles through
all ``n`` validators over ``n`` consecutive rounds, which is what makes T6
("proposer silent/crashed → round timeout triggers, chain continues") work:
after one timeout the next round has a different, ideally correct, leader.

Example
-------
>>> sel = ProposerSelector(("A", "B", "C", "D"), seed=0)
>>> [sel.proposer_for(5, r) for r in range(4)]           # doctest: +SKIP
['C', 'D', 'A', 'B']
>>> sel.is_proposer(sel.proposer_for(5, 2), 5, 2)
True
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Tuple

from src.network.rng import DeterministicRandom


@dataclass(frozen=True)
class ProposerSelector:
    """Maps ``(height, round)`` to exactly one validator id.

    Parameters
    ----------
    validators : Sequence[str]
        The fixed validator set of the run (public keys or node ids).  Order is
        normalised to the given sequence; it must not change during a run.
    seed : int
        Scenario seed used for the deterministic permutation of the leader
        ring.  Two runs with the same seed produce the same leader sequence.

    Notes
    -----
    The selector is immutable and cheap to hash/compare, so it can be handed to
    every node and embedded in scenario files.
    """

    validators: Tuple[str, ...]
    seed: int = 0
    _order: Tuple[str, ...] = field(default=(), compare=False, repr=False)

    def __post_init__(self) -> None:
        validators = tuple(self.validators)
        if not validators:
            raise ValueError("ProposerSelector needs at least one validator")
        if len(set(validators)) != len(validators):
            raise ValueError("validator ids must be unique")
        if any(not isinstance(v, str) or not v for v in validators):
            raise ValueError("validator ids must be non-empty strings")
        order = tuple(
            DeterministicRandom(self.seed, "proposer").shuffled(validators)
        )
        object.__setattr__(self, "validators", validators)
        object.__setattr__(self, "_order", order)

    # -- basic properties -------------------------------------------------

    @property
    def size(self) -> int:
        """Number of validators ``n``."""
        return len(self.validators)

    @property
    def quorum(self) -> int:
        """``2f + 1`` for ``n = 3f + 1`` (rounded down for other sizes)."""
        return 2 * (self.size // 3) + 1 if self.size >= 4 else self.size

    @property
    def engine_order(self) -> Tuple[str, ...]:
        """The permuted leader ring (identical on every node)."""
        return self._order

    # -- selection --------------------------------------------------------

    def proposer_index(self, height: int, round: int) -> int:
        """Index into :attr:`engine_order` of the leader of the slot.

        Raises
        ------
        ValueError
            For negative height or round; they cannot occur in a valid run and
            silently normalising them would hide a consensus bug.
        """
        if height < 0:
            raise ValueError(f"height must be >= 0 (got {height})")
        if round < 0:
            raise ValueError(f"round must be >= 0 (got {round})")
        return (height + round) % self.size

    def proposer_for(self, height: int, round: int) -> str:
        """Validator id that may propose at ``(height, round)``."""
        return self._order[self.proposer_index(height, round)]

    def is_proposer(self, node_id: str, height: int, round: int) -> bool:
        """Whether *node_id* is the leader of the slot."""
        return node_id == self.proposer_for(height, round)

    def next_proposer(self, height: int, round: int) -> str:
        """Leader of the next round (the one a timeout hands over to)."""
        return self.proposer_for(height, round + 1)

    def schedule(self, height: int, rounds: int) -> Tuple[str, ...]:
        """Leaders of ``rounds`` consecutive rounds starting at round 0."""
        if rounds < 0:
            raise ValueError("rounds must be >= 0")
        return tuple(self.proposer_for(height, r) for r in range(rounds))

    def __iter__(self) -> Iterator[str]:
        return iter(self._order)

    def __len__(self) -> int:
        return self.size
