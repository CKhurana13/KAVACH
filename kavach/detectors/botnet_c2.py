"""
Detector 2 — Botnet C2 Beaconing
Signal: inter-arrival time regularity between a given (src, dst) pair
Method: autocorrelation / FFT periodicity score over a rolling history
        of contact timestamps
"""

from __future__ import annotations

from collections import defaultdict, deque

import numpy as np

from common.schema import Alert, ThreatClass, confidence_tier
from detectors.base import BaseDetector
from simulation.traffic_generator import SimulationWindow

MIN_CONTACTS = 4          # need at least this many contacts to judge periodicity
HISTORY_LEN = 20          # rolling window of past contact timestamps kept per pair


def _periodicity_score(times: list[float]) -> tuple[float, float]:
    """Returns (score in [0,1], dominant_period_seconds).
    A perfectly regular beacon has near-zero variance in inter-arrival
    time -> high score. Jittery/human traffic has high variance -> low score.
    """
    if len(times) < MIN_CONTACTS:
        return 0.0, 0.0
    intervals = np.diff(sorted(times))
    if len(intervals) < 2 or np.mean(intervals) == 0:
        return 0.0, 0.0
    cv = np.std(intervals) / np.mean(intervals)  # coefficient of variation
    # low CV -> regular beaconing. Map CV in [0, 1.5] down to score in [1, 0].
    score = float(np.clip(1.0 - cv / 0.5, 0.0, 1.0))

    # cross-check with FFT: a truly periodic signal has one dominant frequency bin
    if len(intervals) >= 4:
        detrended = intervals - np.mean(intervals)
        spectrum = np.abs(np.fft.rfft(detrended))
        if spectrum.sum() > 0:
            dominance = spectrum.max() / (spectrum.sum() + 1e-9)
            score = float(np.clip(0.6 * score + 0.4 * dominance, 0.0, 1.0))
    return score, float(np.mean(intervals))


class BotnetC2Detector(BaseDetector):
    name = "botnet_c2_detector"

    def __init__(self):
        self.history: dict[tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=HISTORY_LEN))
        self._alerted_recently: set[tuple[str, str]] = set()

    def process_window(self, win: SimulationWindow) -> list[Alert]:
        alerts: list[Alert] = []
        pairs_seen_this_window: dict[tuple[str, str], list] = defaultdict(list)

        for f in win.flows:
            key = (f.src_ip, f.dst_ip)
            self.history[key].append(f.timestamp)
            pairs_seen_this_window[key].append(f)

        for key, flows in pairs_seen_this_window.items():
            times = list(self.history[key])
            score, period = _periodicity_score(times)
            if score >= 0.75 and key not in self._alerted_recently:
                src, dst = key
                alerts.append(Alert(
                    threat_class=ThreatClass.BOTNET_C2,
                    confidence=confidence_tier(score),
                    score=round(score, 3),
                    src_ip=src, dst_ip=dst,
                    evidence={
                        "contacts_observed": len(times),
                        "mean_interval_seconds": round(period, 1),
                        "periodicity_score": round(score, 3),
                    },
                    detector=self.name,
                    flow_ids=[f.flow_id for f in flows],
                    timestamp=win.t_start,
                ))
                self._alerted_recently.add(key)
        return alerts
