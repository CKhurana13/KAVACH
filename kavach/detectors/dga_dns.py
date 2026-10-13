"""
Detector 3 — DGA / DNS Tunnelling
Signal: domain entropy, n-gram likelihood, query length & record type
Method: char-level Shannon entropy + a bigram language model fitted on
        benign-looking dictionary words (stands in for a Tranco-benign
        corpus), scored against random/DGA-shaped strings.
"""

from __future__ import annotations

import math
from collections import defaultdict

from common.schema import Alert, ThreatClass, confidence_tier
from detectors.base import BaseDetector
from simulation.traffic_generator import SimulationWindow

# a tiny "benign" reference corpus standing in for a Tranco top-domains list
_BENIGN_WORDS = [
    "mail", "cdn", "static", "api", "login", "assets", "update", "cloud", "app",
    "portal", "secure", "images", "search", "docs", "shop", "news", "video",
    "content", "service", "account", "support", "gateway", "edge", "core",
]

TUNNEL_QTYPES = {"TXT", "NULL"}
SUSPICIOUS_COUNT_THRESHOLD = 8  # >= this many high-entropy queries from one src in a window


def _char_bigram_model(words: list[str]) -> dict[str, float]:
    counts: dict[str, int] = defaultdict(int)
    total = 0
    for w in words:
        w = f"^{w}$"
        for i in range(len(w) - 1):
            counts[w[i:i + 2]] += 1
            total += 1
    return {k: v / total for k, v in counts.items()}


_BIGRAM_MODEL = _char_bigram_model(_BENIGN_WORDS)


def _ngram_likelihood(label: str) -> float:
    """Higher = looks more like the benign corpus. Random DGA strings score low."""
    s = f"^{label}$"
    if len(s) < 2:
        return 1.0
    hits = sum(1 for i in range(len(s) - 1) if s[i:i + 2] in _BIGRAM_MODEL)
    return hits / (len(s) - 1)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


class DGADetector(BaseDetector):
    name = "dga_dns_detector"

    def process_window(self, win: SimulationWindow) -> list[Alert]:
        alerts: list[Alert] = []
        by_src: dict[str, list] = defaultdict(list)
        for rec in win.dns:
            by_src[rec.src_ip].append(rec)

        for src, recs in by_src.items():
            flagged = []
            for rec in recs:
                label = rec.query_name.split(".")[0]
                entropy = _shannon_entropy(label)
                ngram = _ngram_likelihood(label)
                is_suspicious_len = len(rec.query_name) > 40 or rec.qtype in TUNNEL_QTYPES
                # high entropy + low n-gram likelihood + long/tunnel-shaped record = suspicious
                if entropy > 3.3 and ngram < 0.35:
                    flagged.append((rec, entropy, ngram, is_suspicious_len))

            if len(flagged) >= SUSPICIOUS_COUNT_THRESHOLD:
                avg_entropy = sum(e for _, e, _, _ in flagged) / len(flagged)
                avg_ngram = sum(n for _, _, n, _ in flagged) / len(flagged)
                tunnel_shaped = sum(1 for *_, s in flagged if s)
                score = min(1.0, 0.4 * (avg_entropy / 4.5) + 0.3 * (1 - avg_ngram)
                            + 0.3 * (tunnel_shaped / len(flagged)))
                alerts.append(Alert(
                    threat_class=ThreatClass.DGA_DNS,
                    confidence=confidence_tier(score),
                    score=round(score, 3),
                    src_ip=src, dst_ip="dns-resolver",
                    evidence={
                        "suspicious_queries_in_window": len(flagged),
                        "avg_domain_entropy": round(avg_entropy, 2),
                        "avg_ngram_likelihood": round(avg_ngram, 2),
                        "tunnel_record_types_seen": tunnel_shaped,
                        "sample_domains": [r.query_name for r, *_ in flagged[:5]],
                    },
                    detector=self.name,
                    flow_ids=[r.flow_id for r, *_ in flagged],
                    timestamp=win.t_start,
                ))
        return alerts
