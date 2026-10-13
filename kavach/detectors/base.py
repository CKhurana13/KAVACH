from __future__ import annotations

from abc import ABC, abstractmethod

from common.schema import Alert
from simulation.traffic_generator import SimulationWindow


class BaseDetector(ABC):
    """Every detector is a lightweight, independently-crashable unit that
    consumes one SimulationWindow at a time and may emit zero or more
    standardized Alerts. Detectors keep their own small rolling state
    (needed for EWMA/CUSUM, periodicity, IsolationForest baselines, etc.)
    but never talk to each other directly — only the correlation engine
    reads their combined output."""

    name: str = "base"

    @abstractmethod
    def process_window(self, win: SimulationWindow) -> list[Alert]:
        ...

    def safe_process(self, win: SimulationWindow) -> list[Alert]:
        """Wrapper the orchestrator calls. A crashing detector degrades
        gracefully instead of taking the whole pipeline down (per the
        deck's 'Graceful Degradation' differentiator)."""
        try:
            return self.process_window(win)
        except Exception as exc:  # noqa: BLE001
            print(f"[{self.name}] detector error (degraded, skipping window {win.window_id}): {exc}")
            return []
