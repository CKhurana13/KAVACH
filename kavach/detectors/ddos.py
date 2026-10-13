"""
Detector 1 — Volumetric / Protocol DDoS
Signal: packets/sec per destination, SYN ratio, source-IP entropy
Method: EWMA baseline + CUSUM change-point detection
"""

from __future__ import annotations

import math
from collections import defaultdict

from common.schema import Alert, ThreatClass, confidence_tier
from detectors.base import BaseDetector
from simulation.traffic_generator import SimulationWindow, WINDOW_SECONDS


def _entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class DDoSDetector(BaseDetector):
    name = "ddos_detector"

    def __init__(self, ewma_alpha: float = 0.3, cusum_threshold: float = 15.0, baseline_pps: float = 2.0):
        self.alpha = ewma_alpha
        self.cusum_threshold = cusum_threshold
        self.baseline_pps = baseline_pps  # assumed-normal rate for a destination never seen before
        self.ewma_rate: dict[str, float] = {}
        self.cusum: dict[str, float] = defaultdict(float)

    def process_window(self, win: SimulationWindow) -> list[Alert]:
        alerts: list[Alert] = []
        by_dst: dict[str, list] = defaultdict(list)
        for f in win.flows:
            by_dst[f.dst_ip].append(f)

        for dst, flows in by_dst.items():
            pps = len(flows) / WINDOW_SECONDS
            prev_ewma = self.ewma_rate.get(dst, self.baseline_pps)
            new_ewma = self.alpha * pps + (1 - self.alpha) * prev_ewma
            deviation = pps - prev_ewma

            # CUSUM: accumulate positive deviations above a small slack, reset on negative swings
            self.cusum[dst] = max(0.0, self.cusum[dst] + deviation - 1.0)
            self.ewma_rate[dst] = new_ewma

            if self.cusum[dst] > self.cusum_threshold:
                syn_ratio = sum(f.syn_count for f in flows) / max(1, sum(f.packet_count for f in flows))
                src_entropy = _entropy([f.src_ip for f in flows])
                max_entropy = math.log2(max(2, len(flows)))
                norm_entropy = src_entropy / max_entropy if max_entropy > 0 else 0

                score = min(1.0, 0.5 * min(1.0, self.cusum[dst] / (self.cusum_threshold * 2))
                            + 0.25 * syn_ratio + 0.25 * norm_entropy)

                alerts.append(Alert(
                    threat_class=ThreatClass.DDOS,
                    confidence=confidence_tier(score),
                    score=round(score, 3),
                    src_ip="multiple" if norm_entropy > 0.7 else flows[0].src_ip,
                    dst_ip=dst,
                    evidence={
                        "packets_per_sec": round(pps, 1),
                        "baseline_ewma_pps": round(prev_ewma, 1),
                        "cusum_statistic": round(self.cusum[dst], 1),
                        "syn_ratio": round(syn_ratio, 2),
                        "src_ip_entropy_normalized": round(norm_entropy, 2),
                        "distinct_sources": len(set(f.src_ip for f in flows)),
                    },
                    detector=self.name,
                    flow_ids=[f.flow_id for f in flows[:25]],
                    timestamp=win.t_start,
                ))
                self.cusum[dst] = 0.0  # reset after alerting
        return alerts
