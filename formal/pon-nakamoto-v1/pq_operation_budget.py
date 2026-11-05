"""Local absolute-time/cancellation budget for bounded PQ research operations.

This is process-local resource control, never a signed timestamp, replay journal,
chain clock or consensus/Final-use authority. Kernel scheduling and uninterruptible
filesystem calls cannot be made real-time by a Python deadline.
"""
from __future__ import annotations

from contextlib import contextmanager
import math
import threading
import time


class BudgetExpired(TimeoutError):
    """The original operation deadline expired or its owner cancelled it."""


class OperationBudget:
    def __init__(self, deadline: float):
        if type(deadline) not in (float, int) or not math.isfinite(deadline):
            raise ValueError("finite monotonic deadline required")
        self.deadline = deadline
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._aborters = {}

    def remaining(self, cap: float | None = None) -> float:
        if self._cancelled.is_set():
            raise BudgetExpired("bounded operation cancelled")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BudgetExpired("bounded operation deadline expired")
        return remaining if cap is None else min(remaining, cap)

    def check(self) -> None:
        self.remaining()

    @contextmanager
    def abort_on_cancel(self, abort):
        """Register a socket/process abort before its potentially blocking call."""
        token = object()
        with self._lock:
            self.check()
            self._aborters[token] = abort
        try:
            # Cancellation may race registration; the operation must not start
            # after its socket/process was closed by the owner.
            self.check()
            yield
        finally:
            with self._lock:
                self._aborters.pop(token, None)

    def cancel(self) -> None:
        """Wake active blocking work; each owning worker still closes/reaps it."""
        with self._lock:
            self._cancelled.set()
            aborters = tuple(self._aborters.values())
            self._aborters.clear()
        for abort in aborters:
            try:
                abort()
            except OSError:
                # A concurrent normal close/exit is already a successful abort.
                pass
