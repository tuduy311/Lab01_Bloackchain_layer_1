"""Deterministic discrete-event scheduler.

The simulator has no threads and no wall clock: every component (network
delivery, consensus timers, round timeouts) registers a callback at a
simulated timestamp, and the scheduler advances simulation time by executing
those callbacks in timestamp order.  That single design choice is what makes
two runs with the same configuration produce byte-identical logs (Lab01 T8).

Determinism rules
-----------------
* Time is stored as an integer number of ticks (:data:`TIME_QUANTUM` ticks per
  second, i.e. nanosecond resolution).  Floating point seconds are converted
  once through :func:`to_ticks`, so accumulating delays can never drift by an
  ULP and silently reorder two events between runs.
* Two events scheduled for the same tick are executed in the order they were
  created.  Every event therefore carries a monotonically increasing sequence
  number and the heap is ordered by ``(ticks, sequence)``.
* Callbacks must be pure functions of the simulated state (no *time()*, no
  *random*).  Any randomness has to come from a seeded generator, see
  :mod:`src.network.rng`.

Example
-------
>>> sched = Scheduler()
>>> log = []
>>> sched.schedule_after(0.2, log.append, "late")
>>> sched.schedule_after(0.1, log.append, "early")
>>> sched.run()
2
>>> log
['early', 'late']
"""

from __future__ import annotations

import heapq
import math
from typing import Any, Callable, List, Optional, Set, Tuple

TIME_QUANTUM: int = 1_000_000_000
"""Ticks per simulated second (nanosecond resolution)."""


def to_ticks(seconds: float) -> int:
    """Convert simulated seconds to integer ticks.

    Raises
    ------
    ValueError
        If *seconds* is NaN or infinite, which would corrupt the event order.
    """
    value = float(seconds)
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"invalid simulation time: {seconds!r}")
    return int(round(value * TIME_QUANTUM))


def to_seconds(ticks: int) -> float:
    """Convert integer ticks back to simulated seconds."""
    return ticks / TIME_QUANTUM


class EventHandle:
    """Reference returned by :meth:`Scheduler.schedule_at`.

    The handle can be cancelled; a cancelled event is skipped when its time
    comes and never invokes its callback.
    """

    __slots__ = ("id", "time", "tag", "_cancelled")

    def __init__(self, event_id: int, time: float, tag: str = "") -> None:
        self.id = event_id
        self.time = time
        self.tag = tag
        self._cancelled = False

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "cancelled" if self._cancelled else "pending"
        return f"EventHandle(id={self.id}, time={self.time:.9f}, tag={self.tag!r}, {state})"


class Scheduler:
    """Minimal deterministic event loop.

    Parameters
    ----------
    start_time : float
        Initial simulation time in seconds (default ``0.0``).

    Attributes
    ----------
    processed_events : int
        Number of callbacks executed so far.  Used by tests and by the
        determinism checker to prove that both runs did the same work.
    """

    def __init__(self, start_time: float = 0.0) -> None:
        self._now: int = to_ticks(start_time)
        self._heap: List[Tuple[int, int, int, Callable[..., Any], tuple, dict]] = []
        self._sequence: int = 0
        self._next_id: int = 1
        self._live: Set[int] = set()
        self.processed_events: int = 0

    # -- time -------------------------------------------------------------

    @property
    def now(self) -> float:
        """Current simulation time in seconds."""
        return to_seconds(self._now)

    def now_ticks(self) -> int:
        """Current simulation time in nanoseconds (integer, exact)."""
        return self._now

    # -- scheduling -------------------------------------------------------

    def schedule_at(
        self,
        time: float,
        callback: Callable[..., Any],
        *args: Any,
        tag: str = "",
        **kwargs: Any,
    ) -> EventHandle:
        """Register *callback* to run at absolute simulation time *time*.

        Times in the past are clamped to :attr:`now` so a callback can never be
        reordered before already executed work.
        """
        ticks = max(to_ticks(time), self._now)
        return self._push(ticks, callback, args, kwargs, tag)

    def schedule_after(
        self,
        delay: float,
        callback: Callable[..., Any],
        *args: Any,
        tag: str = "",
        **kwargs: Any,
    ) -> EventHandle:
        """Register *callback* to run *delay* seconds from :attr:`now`."""
        if delay < 0:
            raise ValueError(f"negative delay: {delay!r}")
        return self._push(self._now + to_ticks(delay), callback, args, kwargs, tag)

    def _push(
        self,
        ticks: int,
        callback: Callable[..., Any],
        args: tuple,
        kwargs: dict,
        tag: str,
    ) -> EventHandle:
        event_id = self._next_id
        self._next_id += 1
        handle = EventHandle(event_id, to_seconds(ticks), tag)
        self._live.add(event_id)
        heapq.heappush(
            self._heap,
            (ticks, self._sequence, event_id, callback, args, kwargs),
        )
        self._sequence += 1
        return handle

    def cancel(self, handle: Optional[EventHandle]) -> bool:
        """Cancel *handle*; return ``True`` if it was still pending."""
        if handle is None or handle.cancelled:
            return False
        if handle.id not in self._live:
            return False
        handle._cancelled = True
        self._live.discard(handle.id)
        return True

    # -- running ----------------------------------------------------------

    def peek_time(self) -> Optional[float]:
        """Time of the next pending event, or ``None`` when idle."""
        for ticks, _seq, event_id, _cb, _args, _kw in self._heap:
            if event_id in self._live:
                return to_seconds(ticks)
        return None

    def __len__(self) -> int:
        """Number of pending (non-cancelled) events."""
        return len(self._live)

    def step(self) -> bool:
        """Execute the next event.  Return ``False`` if the queue is empty."""
        while self._heap:
            ticks, _seq, event_id, callback, args, kwargs = heapq.heappop(self._heap)
            if event_id not in self._live:
                continue
            self._live.discard(event_id)
            self._now = max(self._now, ticks)
            self.processed_events += 1
            callback(*args, **kwargs)
            return True
        return False

    def run_until(self, end_time: float) -> int:
        """Execute every event with time ``<= end_time``; return how many ran."""
        limit = to_ticks(end_time)
        count = 0
        while self._heap and self._heap[0][0] <= limit:
            if not self.step():
                break
            count += 1
        # Advance the clock to the requested boundary so later events scheduled
        # relative to "now" start from the right point even with an idle queue.
        self._now = max(self._now, limit)
        return count

    def run(self, max_events: Optional[int] = None) -> int:
        """Execute events until the queue drains (or *max_events* is hit)."""
        count = 0
        while self._heap:
            if max_events is not None and count >= max_events:
                break
            if not self.step():
                break
            count += 1
        return count
