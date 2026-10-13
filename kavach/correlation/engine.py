"""
Correlation Engine — the deck's core innovation.

Rule-based (deliberately not ML — see Feasibility slide: "Correlation logic
is simple rule-based escalation, not ML"). Watches the combined stream of
alerts from all 6 detectors and links weak, independent signals that share
an actor (src or dst IP) within a rolling time window into a single
high-confidence, explainable kill-chain alert:

    Recon/Scan  ->  C2 Beacon  ->  Exfiltration

Any 2-of-3 stages sharing an IP within CORRELATION_WINDOW_SECONDS is enough
to escalate — real attacks don't always hit every stage in a way we observe.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from common.schema import Alert, ThreatClass, Confidence

CORRELATION_WINDOW_SECONDS = 60.0
KILL_CHAIN_ORDER = [ThreatClass.RECON_SCAN, ThreatClass.BOTNET_C2, ThreatClass.EXFILTRATION]


@dataclass
class KillChainMatch:
    stages: list[Alert]
    shared_ip: str


class CorrelationEngine:
    def __init__(self, window_seconds: float = CORRELATION_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        self.recent_alerts: deque[Alert] = deque()
        self._already_escalated: set[frozenset] = set()

    def _prune(self, now: float):
        while self.recent_alerts and (now - self.recent_alerts[0].timestamp) > self.window_seconds:
            self.recent_alerts.popleft()

    def ingest(self, alerts: list[Alert], now: float) -> list[Alert]:
        """Feed this window's fresh detector alerts in; get back any newly
        escalated kill-chain alerts (in addition to the originals, which
        the caller should still keep/display)."""
        self.recent_alerts.extend(alerts)
        self._prune(now)

        escalations: list[Alert] = []
        candidate_ips = set()
        for a in self.recent_alerts:
            if a.threat_class in KILL_CHAIN_ORDER:
                candidate_ips.add(a.src_ip)
                candidate_ips.add(a.dst_ip)

        for ip in candidate_ips:
            stage_hits: dict[ThreatClass, Alert] = {}
            for a in self.recent_alerts:
                if a.threat_class in KILL_CHAIN_ORDER and ip in (a.src_ip, a.dst_ip):
                    # keep the highest-scoring alert seen per stage for this ip
                    if a.threat_class not in stage_hits or a.score > stage_hits[a.threat_class].score:
                        stage_hits[a.threat_class] = a

            if len(stage_hits) >= 2:
                key = frozenset((ip, tuple(sorted(a.alert_id for a in stage_hits.values()))))
                if key in self._already_escalated:
                    continue
                self._already_escalated.add(key)

                stages_present = [tc.value for tc in KILL_CHAIN_ORDER if tc in stage_hits]
                combined_score = min(1.0, sum(a.score for a in stage_hits.values()) / len(stage_hits) + 0.1 * len(stage_hits))
                all_flow_ids = [fid for a in stage_hits.values() for fid in a.flow_ids][:40]

                escalations.append(Alert(
                    threat_class=ThreatClass.KILL_CHAIN,
                    confidence=Confidence.CRITICAL,
                    score=round(combined_score, 3),
                    src_ip=ip, dst_ip="multiple" if len(stage_hits) > 1 else next(iter(stage_hits.values())).dst_ip,
                    evidence={
                        "linked_stages": stages_present,
                        "stage_count": len(stage_hits),
                        "stage_alert_ids": [a.alert_id for a in stage_hits.values()],
                        "narrative": " -> ".join(stages_present),
                    },
                    detector="correlation_engine",
                    flow_ids=all_flow_ids,
                    timestamp=now,
                ))
        return escalations
