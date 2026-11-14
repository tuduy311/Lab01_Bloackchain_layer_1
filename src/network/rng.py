"""Seeded pseudo-random streams for reproducible fault injection.

The lab requires that the same configuration and seed produce byte-identical
logs, so no component may touch :mod:`random` or *os.urandom* directly.
Instead every component derives its own independent stream from one global
seed::

    rng = DeterministicRandom(seed=7, stream="link:node_1->node_2")

Independent streams matter for reproducibility: an extra draw on one link
(``drop`` vs ``no drop``) must not shift the draws of every other link,
otherwise adding one node silently rewrites the whole fault pattern.

Draws that need to be a pure function of a key (no stream position) use
:func:`hash_to_unit`, e.g. deterministic jitter for round timeouts.
"""

from __future__ import annotations

import hashlib
import random
from typing import Iterable, List, Sequence, TypeVar

T = TypeVar("T")

_UINT64 = 1 << 64


def derive_seed(seed: int, stream: str) -> int:
    """Derive a 64-bit sub-seed for *stream* from the global *seed*.

    Uses SHA-256 so the mapping is stable across Python versions and
    platforms (``hash()`` is salted and would break reproducibility).
    """
    digest = hashlib.sha256(f"{seed}:{stream}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def hash_to_unit(*parts: object) -> float:
    """Map an arbitrary key to a deterministic float in ``[0, 1)``.

    Useful for key-addressed randomness (e.g. jitter of ``(height, round)``)
    that must not depend on how many other draws happened before.
    """
    key = ":".join(str(p) for p in parts).encode("utf-8")
    digest = hashlib.sha256(key).digest()
    return int.from_bytes(digest[:8], "big") / _UINT64


class DeterministicRandom:
    """A reproducible random stream.

    Parameters
    ----------
    seed : int
        Global simulation seed.
    stream : str
        Logical name of the stream; two components with different names get
        uncorrelated sequences derived from the same seed.

    Notes
    -----
    The underlying generator is :class:`random.Random` (Mersenne Twister),
    whose sequence for a given integer seed is part of CPython's stable
    behaviour.  :meth:`shuffled` implements Fisher-Yates explicitly instead of
    delegating to :meth:`random.Random.shuffle` so that a future change to the
    standard library cannot reorder validator sets between runs.
    """

    def __init__(self, seed: int, stream: str = "main") -> None:
        self.seed = seed
        self.stream = stream
        self._rng = random.Random(derive_seed(seed, stream))
        self.draws = 0

    # -- primitives -------------------------------------------------------

    def random(self) -> float:
        """Uniform float in ``[0, 1)``."""
        self.draws += 1
        return self._rng.random()

    def uniform(self, low: float, high: float) -> float:
        """Uniform float in ``[low, high]`` (``low`` if equal)."""
        self.draws += 1
        return self._rng.uniform(low, high)

    def randint(self, low: int, high: int) -> int:
        """Uniform integer in ``[low, high]`` (both inclusive)."""
        self.draws += 1
        return self._rng.randint(low, high)

    def chance(self, probability: float) -> bool:
        """``True`` with the given *probability* (always consumes one draw)."""
        if probability <= 0.0:
            return False
        if probability >= 1.0:
            self.draws += 1
            self._rng.random()
            return True
        return self.random() < probability

    def choice(self, items: Sequence[T]) -> T:
        """Pick one element uniformly."""
        if not items:
            raise ValueError("cannot choose from an empty sequence")
        return items[self.randint(0, len(items) - 1)]

    def shuffled(self, items: Iterable[T]) -> List[T]:
        """Return a deterministically shuffled list (Fisher-Yates)."""
        out = list(items)
        for i in range(len(out) - 1, 0, -1):
            j = self._rng.randrange(i + 1)
            self.draws += 1
            out[i], out[j] = out[j], out[i]
        return out

    # -- composition ------------------------------------------------------

    def fork(self, sub_stream: str) -> "DeterministicRandom":
        """Create a child stream that is independent of this one's position."""
        return DeterministicRandom(self.seed, f"{self.stream}/{sub_stream}")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"DeterministicRandom(seed={self.seed}, stream={self.stream!r}, draws={self.draws})"
