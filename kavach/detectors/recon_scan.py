"""
Detector 5 — Reconnaissance / Port Scanning
Signal: fan-out ratio (unique destination IPs/ports contacted by one source)
Method: threshold + entropy scoring
"""

from __future__ import annotations

import math
from collections import defaultdict

from common.schema import Alert, ThreatClass, confidence_tier
from detectors.base import BaseDetector
from simulation.traffic_generator import SimulationWindow

FANOUT_THRESHOLD = 25  # unique dst:port pairs from one src within a window


def _entropy(values: list) -> float:
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values()) if n else 0.0


class ReconScanDetector(BaseDetector):
    name = "recon_scan_detector"

    def process_window(self, win: SimulationWindow) -> list[Alert]:
        alerts: list[Alert] = []
        by_src: dict[str, list] = defaultdict(list)
        for f in win.flows:
            by_src[f.src_ip].append(f)

        for src, flows in by_src.items():
            targets = set((f.dst_ip, f.dst_port) for f in flows)
            fanout = len(targets)
            if fanout < FANOUT_THRESHOLD:
                continue

            dst_ips = [f.dst_ip for f in flows]
            dst_ports = [f.dst_port for f in flows]
            ip_entropy = _entropy(dst_ips) / max(1e-9, math.log2(max(2, len(set(dst_ips)))))
            port_entropy = _entropy(dst_ports) / max(1e-9, math.log2(max(2, len(set(dst_ports)))))

            score = min(1.0, 0.5 * min(1.0, fanout / 150) + 0.25 * ip_entropy + 0.25 * port_entropy)
            alerts.append(Alert(
                threat_class=ThreatClass.RECON_SCAN,
                confidence=confidence_tier(score),
                score=round(score, 3),
                src_ip=src, dst_ip=f"{len(set(dst_ips))} distinct hosts",
                evidence={
                    "fanout_unique_dst_port_pairs": fanout,
                    "distinct_dst_ips": len(set(dst_ips)),
                    "distinct_dst_ports": len(set(dst_ports)),
                    "dst_ip_entropy_normalized": round(ip_entropy, 2),
                    "dst_port_entropy_normalized": round(port_entropy, 2),
                },
                detector=self.name,
                flow_ids=[f.flow_id for f in flows[:30]],
                timestamp=win.t_start,
            ))
        return alerts
