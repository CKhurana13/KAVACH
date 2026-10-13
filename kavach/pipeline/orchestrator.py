from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from common.schema import Alert
from correlation.engine import CorrelationEngine
from detectors.base import BaseDetector
from detectors.botnet_c2 import BotnetC2Detector
from detectors.ddos import DDoSDetector
from detectors.dga_dns import DGADetector
from detectors.encrypted_malware import EncryptedMalwareDetector
from detectors.exfiltration import ExfiltrationDetector
from detectors.recon_scan import ReconScanDetector
from simulation.traffic_generator import SCENARIOS, SimulationWindow, TrafficGenerator


def build_detectors() -> dict[str, BaseDetector]:
    return {
        "ddos": DDoSDetector(),
        "botnet_c2": BotnetC2Detector(),
        "dga_dns": DGADetector(),
        "encrypted_malware": EncryptedMalwareDetector(),
        "recon_scan": ReconScanDetector(),
        "exfiltration": ExfiltrationDetector(),
    }


@dataclass
class WindowResult:
    window: SimulationWindow
    detector_alerts: list[Alert] = field(default_factory=list)
    kill_chain_alerts: list[Alert] = field(default_factory=list)
    flows_processed: int = 0
    dns_processed: int = 0


class KavachPipeline:
    """Runs the full KAVACH flow one window at a time:
    ingest -> 6 parallel detectors -> correlation engine -> alerts.
    No external broker — this loop *is* the streaming side-car, just
    in-process for the demo instead of fronted by Kafka/Redpanda."""

    def __init__(self, seed: int | None = None, kill_chain_start_window: int = 6):
        self.generator = TrafficGenerator(seed=seed, kill_chain_start_window=kill_chain_start_window)
        self.detectors = build_detectors()
        self.correlator = CorrelationEngine()
        self.all_alerts: list[Alert] = []

    def run_window(self, win: SimulationWindow) -> WindowResult:
        result = WindowResult(window=win, flows_processed=len(win.flows), dns_processed=len(win.dns))
        for det in self.detectors.values():
            alerts = det.safe_process(win)
            result.detector_alerts.extend(alerts)
        self.all_alerts.extend(result.detector_alerts)

        kill_chain = self.correlator.ingest(result.detector_alerts, now=win.t_start)
        result.kill_chain_alerts.extend(kill_chain)
        self.all_alerts.extend(kill_chain)
        return result

    def stream(self, n_windows: int) -> Iterator[WindowResult]:
        for win in self.generator.stream(n_windows):
            yield self.run_window(win)

    def stream_scenario(self, scenario: str, n_windows: int = 12) -> Iterator[WindowResult]:
        """Run a single named scenario (one attack type, the full kill
        chain, or 'all') on a deterministic schedule. See
        simulation.traffic_generator.SCENARIOS for the valid keys."""
        for win in self.generator.stream_scenario(scenario, n_windows):
            yield self.run_window(win)
