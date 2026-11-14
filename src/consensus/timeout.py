"""Round timeouts for the BFT state machine.

Liveness in a partially synchronous network needs exactly one rule: when the
current round does not reach a decision within a bounded time, the node moves
to ``round + 1``.  Who triggers that, and with what delay, must itself be
deterministic, otherwise two runs of the same scenario would advance rounds at
different simulated times and produce different logs.

Design
------
* :class:`TimeoutConfig` computes the timeout of ``(height, round)``:
  ``min(base * multiplier**round, max_timeout)`` scaled by a *deterministic*
  jitter derived from ``sha256(seed:height:round)``.  The jitter is a pure
  function of the slot, so it is reproducible and it cannot shift other slots.
* :class:`RoundTimer` wraps one scheduler event and is safe to cancel.
* :class:`TimeoutManager` owns the timer of the *current* slot:
  - ``start(height, round)`` arms the timer for the slot;
  - firing calls ``on_timeout(height, round)`` **exactly once** per slot;
  - stale timers (a late fire for a slot the node already left) are ignored by
    a monotonically increasing token;
  - ``stop()`` disarms the timer, e.g. right before finalizing a block.

The engine (TV1) only has to call ``start`` when it enters a round, ``stop``
when it finalizes, and advance ``round`` inside its ``on_timeout`` callback.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from src.scheduler import EventHandle, Scheduler


@dataclass(frozen=True)
class TimeoutConfig:
    """Timeout schedule parameters.

    Parameters
    ----------
    base : float
        Timeout of round 0 in simulated seconds.  Should be a small multiple of
        the network synchrony bound Δ so a correct leader has time to deliver.
    multiplier : float
        Growth factor per round (``> 1`` gives the usual exponential backoff).
    max_timeout : float
        Upper bound of the timeout, keeps a long-stalled height responsive.
    jitter : float
        Relative jitter in ``[0, 1)``; ``0`` means deterministic timeouts
        (recommended for reproducible logs, non-zero values are deterministic
        too because they are hashed from the slot).
    seed : int
        Seed used by the jitter hash.
    max_round : int
        Exponent cap so ``multiplier**round`` cannot overflow before the
        ``max_timeout`` clamp on very long stalls.
    """

    base: float = 1.0
    multiplier: float = 1.5
    max_timeout: float = 30.0
    jitter: float = 0.0
    seed: int = 0
    max_round: int = 64

    def validate(self) -> None:
        """Raise :class:`ValueError` on an unusable schedule."""
        if self.base <= 0:
            raise ValueError("timeout base must be > 0")
        if self.multiplier < 1.0:
            raise ValueError("timeout multiplier must be >= 1.0")
        if self.max_timeout < self.base:
            raise ValueError("max_timeout must be >= base")
        if not 0.0 <= self.jitter < 1.0:
            raise ValueError("jitter must be in [0, 1)")
        if self.max_round < 0:
            raise ValueError("max_round must be >= 0")

    def jitter_factor(self, height: int, round: int) -> float:
        """Deterministic multiplier in ``[1 - jitter, 1 + jitter]``."""
        if self.jitter <= 0.0:
            return 1.0
        digest = hashlib.sha256(
            f"{self.seed}:{height}:{round}".encode("utf-8")
        ).digest()
        unit = int.from_bytes(digest[:8], "big") / float(1 << 64)
        return 1.0 + self.jitter * (2.0 * unit - 1.0)

    def duration(self, height: int, round: int) -> float:
        """Timeout length in simulated seconds for ``(height, round)``."""
        exponent = min(max(int(round), 0), self.max_round)
        raw = self.base * (self.multiplier ** exponent)
        capped = min(raw, self.max_timeout)
        return capped * self.jitter_factor(height, round)


class RoundTimer:
    """One cancellable timeout event on the scheduler."""

    def __init__(
        self,
        scheduler: Scheduler,
        duration: float,
        callback: Callable[[], None],
        tag: str = "",
    ) -> None:
        if duration < 0:
            raise ValueError("duration must be >= 0")
        self.scheduler = scheduler
        self.duration = duration
        self._callback = callback
        self._handle: Optional[EventHandle] = (
            scheduler.schedule_after(duration, self._fire, tag=tag or "round-timeout")
        )
        self._fired = False
        self._cancelled = False

    def _fire(self) -> None:
        if self._cancelled:
            return
        self._fired = True
        self._callback()

    def cancel(self) -> bool:
        """Disarm the timer; returns ``True`` if it was still pending."""
        if self._fired or self._cancelled:
            return False
        self._cancelled = True
        return self.scheduler.cancel(self._handle)

    @property
    def fired(self) -> bool:
        return self._fired

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def pending(self) -> bool:
        return not self._fired and not self._cancelled

    @property
    def deadline(self) -> float:
        """Absolute simulation time at which this timer fires."""
        return (self._handle.time if self._handle else self.scheduler.now)


class TimeoutManager:
    """Arms/disarms the round timer and reports round transitions.

    Parameters
    ----------
    scheduler : Scheduler
        Simulation clock.
    on_timeout : Callable[[int, int], None]
        Called once per slot as ``on_timeout(height, round)``.  The callback is
        expected to bump ``round`` and call :meth:`start` again.
    config : TimeoutConfig, optional
        Timeout schedule; defaults to ``base=1.0s``, exponential backoff.

    Attributes
    ----------
    fired_slots : tuple[tuple[int, int], ...]
        Slots whose timeout already fired, in firing order (useful for T6).
    """

    def __init__(
        self,
        scheduler: Scheduler,
        on_timeout: Optional[Callable[[int, int], None]] = None,
        config: Optional[TimeoutConfig] = None,
    ) -> None:
        self.scheduler = scheduler
        self.config = config or TimeoutConfig()
        self.config.validate()
        self._on_timeout = on_timeout
        self._timer: Optional[RoundTimer] = None
        self._slot: Optional[Tuple[int, int]] = None
        self._token = 0
        self._fired: Dict[Tuple[int, int], int] = {}
        self.fired_slots: list = []

    # -- callbacks --------------------------------------------------------

    def set_callback(self, on_timeout: Callable[[int, int], None]) -> None:
        """Install/replace the timeout callback."""
        self._on_timeout = on_timeout

    # -- arming -----------------------------------------------------------

    @property
    def active_slot(self) -> Optional[Tuple[int, int]]:
        """Slot whose timer is currently armed, if any."""
        return self._slot if self._timer is not None and self._timer.pending else None

    @property
    def deadline(self) -> Optional[float]:
        """Absolute time of the armed timeout, or ``None``."""
        return self._timer.deadline if self.active_slot is not None else None

    def start(self, height: int, round: int) -> float:
        """Arm the timeout of ``(height, round)``; returns its duration.

        Arming a new slot cancels the previous timer, which is how a node
        leaves a round early (quorum reached before the deadline).
        """
        slot = (int(height), int(round))
        self.stop()
        duration = self.config.duration(*slot)
        if slot in self._fired:
            # A slot is never re-timed after it already timed out; the caller
            # is out of sync (e.g. it re-entered a finished round).
            self._slot = None
            return 0.0
        self._slot = slot
        self._token += 1
        token = self._token
        self._timer = RoundTimer(
            self.scheduler,
            duration,
            lambda: self._fire(slot, token),
            tag=f"timeout:{slot[0]}:{slot[1]}",
        )
        return duration

    def stop(self) -> bool:
        """Disarm the current timer; ``True`` if one was armed."""
        if self._timer is None:
            return False
        was_pending = self._timer.cancel()
        self._timer = None
        self._slot = None
        return was_pending

    # -- firing -----------------------------------------------------------

    def _fire(self, slot: Tuple[int, int], token: int) -> None:
        if token != self._token:
            return  # stale timer of a round we already left
        if self._slot != slot:
            return
        if slot in self._fired:
            return
        self._slot = None
        self._timer = None
        self._fired[slot] = self.scheduler.now_ticks()
        self.fired_slots.append(slot)
        if self._on_timeout is not None:
            self._on_timeout(*slot)

    # -- queries ----------------------------------------------------------

    def has_fired(self, height: int, round: int) -> bool:
        return (int(height), int(round)) in self._fired

    def fired_at(self, height: int, round: int) -> Optional[float]:
        """Simulated time the slot timed out, or ``None``."""
        ticks = self._fired.get((int(height), int(round)))
        return None if ticks is None else ticks / 1_000_000_000

    def fired_rounds(self, height: int) -> Tuple[int, ...]:
        """Rounds of *height* that timed out, sorted."""
        return tuple(sorted(r for (h, r) in self._fired if h == int(height)))

    def reset(self) -> None:
        """Drop all state (new height / new run).  Does not fire callbacks."""
        self.stop()
        self._fired.clear()
        self.fired_slots.clear()
        self._token += 1
