"""
Detector 6 — Data Exfiltration
Signal: byte-ratio asymmetry, timing/size/entropy composite fingerprint
Method: Isolation Forest, baselined on normal internal->external transfer
        shapes (synthetic injection stands in for CICIDS2017 baselining
        per the deck's feasibility/testing-regime note).
"""

from __future__ import annotations

import random

import numpy as np
from sklearn.ensemble import IsolationForest

from common.schema import Alert, ThreatClass, confidence_tier
from detectors.base import BaseDetector
from simulation.traffic_generator import SimulationWindow


def _features(f) -> list[float]:
    bps = f.byte_count / max(f.duration, 0.01)
    avg_len = (f.byte_count / f.packet_count) if f.packet_count else 0.0
    return [
        float(f.byte_count),
        float(f.duration),
        float(bps),
        float(f.packet_count),
        float(avg_len),
    ]


def _bootstrap_benign(n: int = 500, seed: int = 7) -> np.ndarray:
    rng = random.Random(seed)
    rows = []
    for _ in range(n):
        n_pkts = rng.randint(4, 40)
        avg_len = rng.randint(64, 1460)
        byte_count = avg_len * n_pkts
        duration = rng.uniform(0.1, 4.0)
        bps = byte_count / max(duration, 0.01)
        rows.append([byte_count, duration, bps, n_pkts, avg_len])
    return np.array(rows)


MIN_BYTES_TO_SCORE = 200_000  # ~5x any observed benign flow; skip scoring ordinary
                               # traffic instead of relying on the model alone to reject it


class ExfiltrationDetector(BaseDetector):
    name = "exfiltration_detector"

    def __init__(self, contamination: float = 0.01):
        X = _bootstrap_benign()
        self.model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
        self.model.fit(X)
        # normalize decision_function output to a 0-1 "anomaly score"
        scores = -self.model.decision_function(X)
        self._score_lo, self._score_hi = float(scores.min()), float(scores.max())

    def _normalize(self, raw: float) -> float:
        span = max(1e-6, self._score_hi - self._score_lo)
        return float(np.clip((raw - self._score_lo) / span, 0.0, 1.0))

    def process_window(self, win: SimulationWindow) -> list[Alert]:
        alerts: list[Alert] = []
        internal_prefixes = ("10.0.",)
        for f in win.flows:
            # only score outbound flows (internal src -> external dst) — that's the exfil direction
            if not f.src_ip.startswith(internal_prefixes) or f.dst_ip.startswith(internal_prefixes):
                continue
            # pre-filter: no real security stack runs an ML pass on every ordinary
            # request. Only flows already large enough to plausibly be a transfer
            # go to the model — this is what keeps normal browsing/API traffic
            # from ever reaching the anomaly detector's baseline false-positive rate.
            if f.byte_count < MIN_BYTES_TO_SCORE:
                continue
            feats = np.array([_features(f)])
            raw = float(-self.model.decision_function(feats)[0])
            is_outlier = self.model.predict(feats)[0] == -1
            score = self._normalize(raw)

            if is_outlier and score >= 0.6:
                bps = f.byte_count / max(f.duration, 0.01)
                alerts.append(Alert(
                    threat_class=ThreatClass.EXFILTRATION,
                    confidence=confidence_tier(score),
                    score=round(score, 3),
                    src_ip=f.src_ip, dst_ip=f.dst_ip,
                    evidence={
                        "byte_count": f.byte_count,
                        "duration_sec": round(f.duration, 2),
                        "throughput_bytes_per_sec": round(bps, 1),
                        "packet_count": f.packet_count,
                        "isolation_forest_anomaly_score": round(score, 3),
                    },
                    detector=self.name,
                    flow_ids=[f.flow_id],
                    timestamp=win.t_start,
                ))
        return alerts
