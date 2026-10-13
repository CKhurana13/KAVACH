"""
KAVACH — Common data schema.

Everything that flows through the pipeline (raw traffic, detector alerts,
correlated kill-chain alerts) is defined here so every module — generator,
detectors, correlation engine, dashboard — agrees on one shape.
"""

from __future__ import annotations

import itertools
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


# ----------------------------------------------------------------------------
# Raw traffic records (what the "shared ingestion layer" hands to detectors)
# ----------------------------------------------------------------------------

_flow_id_counter = itertools.count(1)


@dataclass
class FlowRecord:
    """One network flow, as you'd get from PCAP-derived flow export
    (NetFlow/IPFIX/sFlow) on a passive/unidirectional tap."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" | "UDP" | "ICMP"
    packet_count: int
    byte_count: int
    duration: float  # seconds
    packet_lengths: list[int] = field(default_factory=list)  # first 10-20 pkts (SPLT)
    packet_times: list[float] = field(default_factory=list)  # inter-arrival raw times
    syn_count: int = 0
    ja4: Optional[str] = None  # JA4 TLS client fingerprint, if TLS
    flow_id: str = field(default_factory=lambda: f"flow-{next(_flow_id_counter)}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DNSRecord:
    """One DNS query observed on the passive tap."""

    timestamp: float
    src_ip: str
    query_name: str
    qtype: str  # "A" | "TXT" | "NULL" | ...
    response_len: int = 0
    flow_id: str = field(default_factory=lambda: f"dns-{next(_flow_id_counter)}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ----------------------------------------------------------------------------
# Standardized alert schema (the deck's "one JSON format" differentiator)
# ----------------------------------------------------------------------------

class ThreatClass(str, Enum):
    DDOS = "volumetric_protocol_ddos"
    BOTNET_C2 = "botnet_c2_beaconing"
    DGA_DNS = "dga_dns_tunnelling"
    ENCRYPTED_MALWARE = "malware_in_encrypted_sessions"
    RECON_SCAN = "reconnaissance_port_scanning"
    EXFILTRATION = "data_exfiltration"
    KILL_CHAIN = "correlated_kill_chain"  # emitted only by the correlation engine


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"  # reserved for correlated kill-chain alerts


def confidence_tier(score: float) -> Confidence:
    """Map a detector's raw 0-1 anomaly score to a human confidence tier."""
    if score >= 0.90:
        return Confidence.HIGH
    if score >= 0.70:
        return Confidence.MEDIUM
    return Confidence.LOW


@dataclass
class Alert:
    """The single standardized alert format every detector (and the
    correlation engine) emits. This is what the dashboard renders."""

    threat_class: ThreatClass
    confidence: Confidence
    score: float  # raw 0-1 anomaly/model score behind the confidence tier
    src_ip: str
    dst_ip: str
    evidence: dict[str, Any]              # "why flagged" — feature values, not raw payload
    detector: str                         # which module raised this
    flow_ids: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["threat_class"] = self.threat_class.value
        d["confidence"] = self.confidence.value
        return d
