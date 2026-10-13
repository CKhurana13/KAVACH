"""
KAVACH — Synthetic passive-tap traffic generator.

No real PCAP/dataset access in this environment, so this module plays the
role of "shared ingestion layer" input: it emits realistic-shaped
FlowRecord/DNSRecord batches, one WINDOW_SECONDS-wide window at a time,
mixing:
  - continuous benign background traffic (web browsing, DNS, etc.)
  - independent attack injections (DDoS, DGA tunnelling, encrypted malware)
  - one multi-stage "kill chain" campaign per run (recon -> C2 -> exfil),
    all from the same attacker IP, so the correlation engine has something
    real to link.

Every injected event carries a ground_truth label so the dashboard can show
detected-vs-actual — useful for a judging demo, not something a real deployment
would have.
"""

from __future__ import annotations

import math
import random
import string
import time
from dataclasses import dataclass, field
from typing import Iterator

from common.schema import FlowRecord, DNSRecord

WINDOW_SECONDS = 5.0

BENIGN_JA4_POOL = ["t13d1516h2_8daaf6152771_02713d6af862", "t13d1715h2_5b57614c22b0_3d5424432f57"]
MALICIOUS_JA4_POOL = ["t13d190900_9dc949149365_97f8aa674fd9"]  # abuse.ch-style known-bad fingerprint

INTERNAL_SUBNET = "10.0.{}.{}"
EXTERNAL_POOL = [f"185.220.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(40)]

_random_word_pool = ["mail", "cdn", "static", "api", "login", "assets", "update", "cloud", "app", "portal"]


def _rand_internal_ip() -> str:
    return INTERNAL_SUBNET.format(random.randint(0, 5), random.randint(2, 254))


def _rand_external_ip() -> str:
    return random.choice(EXTERNAL_POOL)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _random_dga_domain() -> str:
    length = random.randint(12, 22)
    label = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    tld = random.choice(["com", "net", "info", "top"])
    return f"{label}.{tld}"


def _benign_domain() -> str:
    return f"{random.choice(_random_word_pool)}.{random.choice(['example', 'contoso', 'corp'])}.com"


@dataclass
class InjectedEvent:
    window: int
    threat_class: str
    attacker_ip: str
    victim_ip: str
    note: str


@dataclass
class SimulationWindow:
    window_id: int
    t_start: float
    t_end: float
    flows: list[FlowRecord] = field(default_factory=list)
    dns: list[DNSRecord] = field(default_factory=list)
    ground_truth: list[InjectedEvent] = field(default_factory=list)


# ----------------------------------------------------------------------------
# Scenario catalog — drives the dashboard's "simulate one attack" buttons and
# the "simulate all" mode. Keys are what callers pass to `stream_scenario`.
# ----------------------------------------------------------------------------

SCENARIOS: dict[str, str] = {
    "ddos": "Volumetric / Protocol DDoS",
    "botnet_c2": "Botnet C2 Beaconing",
    "dga_dns": "DGA / DNS Tunnelling",
    "encrypted_malware": "Malware in Encrypted Sessions",
    "recon_scan": "Reconnaissance / Port Scanning",
    "exfiltration": "Data Exfiltration",
    "kill_chain": "Full Kill Chain (Recon -> C2 -> Exfil)",
    "all": "All Attacks Simultaneously",
}


class TrafficGenerator:
    """Call `.stream(n_windows)` to get an iterator of SimulationWindow.
    Each call to next() advances simulated time by WINDOW_SECONDS."""

    def __init__(self, seed: int | None = None, kill_chain_start_window: int = 6):
        self.rng = random.Random(seed)
        self.t0 = time.time()
        self.kill_chain_start_window = kill_chain_start_window
        # persistent actors so beaconing / kill-chain have continuity across windows
        self.c2_bot_ip = _rand_internal_ip()
        self.c2_server_ip = _rand_external_ip()
        self.c2_interval = 45.0  # seconds between beacons
        self.c2_last_beacon = None
        self.attacker_ip = _rand_external_ip()
        self.kill_chain_victim = _rand_internal_ip()
        self._kill_chain_stage = 0  # 0=idle,1=recon done,2=c2 done,3=exfil done
        # dedicated actors for standalone single-attack demos, kept separate
        # from the kill-chain actors above so single-attack buttons never
        # cross-trigger the correlation engine
        self.demo_c2_bot_ip = _rand_internal_ip()
        self.demo_c2_server_ip = _rand_external_ip()
        self.demo_recon_attacker = _rand_external_ip()
        self.demo_recon_victim_base = _rand_internal_ip().rsplit(".", 1)[0]
        self.demo_exfil_victim = _rand_internal_ip()
        self.demo_exfil_attacker = _rand_external_ip()

    # -- benign traffic -----------------------------------------------------

    def _benign_flows(self, t_start: float) -> list[FlowRecord]:
        flows = []
        for _ in range(self.rng.randint(15, 30)):
            src = _rand_internal_ip()
            dst = _rand_external_ip()
            n_pkts = self.rng.randint(4, 40)
            lengths = [self.rng.randint(64, 1460) for _ in range(min(n_pkts, 20))]
            flows.append(FlowRecord(
                timestamp=t_start + self.rng.uniform(0, WINDOW_SECONDS),
                src_ip=src, dst_ip=dst,
                src_port=self.rng.randint(1024, 65535), dst_port=self.rng.choice([443, 443, 443, 80, 22]),
                protocol="TCP",
                packet_count=n_pkts,
                byte_count=sum(lengths) * max(1, n_pkts // 20),
                duration=self.rng.uniform(0.1, 4.0),
                packet_lengths=lengths,
                packet_times=sorted(self.rng.uniform(0, 2.0) for _ in range(len(lengths))),
                syn_count=1,
                ja4=self.rng.choice(BENIGN_JA4_POOL),
            ))
        return flows

    def _benign_dns(self, t_start: float) -> list[DNSRecord]:
        out = []
        for _ in range(self.rng.randint(5, 12)):
            out.append(DNSRecord(
                timestamp=t_start + self.rng.uniform(0, WINDOW_SECONDS),
                src_ip=_rand_internal_ip(),
                query_name=_benign_domain(),
                qtype="A",
                response_len=self.rng.randint(40, 90),
            ))
        return out

    # -- attack injections ---------------------------------------------------

    def _inject_ddos(self, win: SimulationWindow):
        victim = _rand_internal_ip()
        n_sources = self.rng.randint(150, 400)
        for _ in range(n_sources):
            win.flows.append(FlowRecord(
                timestamp=win.t_start + self.rng.uniform(0, WINDOW_SECONDS),
                src_ip=_rand_external_ip(),  # spoofed / botnet sources -> high src-IP entropy
                dst_ip=victim,
                src_port=self.rng.randint(1024, 65535), dst_port=80,
                protocol="TCP",
                packet_count=self.rng.randint(1, 3),
                byte_count=self.rng.randint(40, 120),
                duration=0.01,
                packet_lengths=[60], packet_times=[0.0],
                syn_count=1,  # SYN flood: every "flow" is just a SYN, ratio ~1.0
            ))
        win.ground_truth.append(InjectedEvent(win.window_id, "volumetric_protocol_ddos",
                                               "many-spoofed", victim, f"{n_sources} src IPs, SYN flood"))

    def _inject_dga(self, win: SimulationWindow):
        bot = _rand_internal_ip()
        for _ in range(self.rng.randint(20, 40)):
            dom = _random_dga_domain()
            win.dns.append(DNSRecord(
                timestamp=win.t_start + self.rng.uniform(0, WINDOW_SECONDS),
                src_ip=bot, query_name=dom,
                qtype=self.rng.choice(["TXT", "NULL", "A"]),
                response_len=self.rng.randint(150, 400),  # tunnelled payload -> bigger than normal
            ))
        win.ground_truth.append(InjectedEvent(win.window_id, "dga_dns_tunnelling", bot, "C2-via-DNS",
                                               "high-entropy DGA domains, TXT/NULL tunnelling"))

    def _inject_encrypted_malware(self, win: SimulationWindow):
        bot = _rand_internal_ip()
        c2 = _rand_external_ip()
        # fixed-size, rhythmic packets -> classic C2/exfil-over-TLS shape, vs bursty benign browsing
        lengths = [512] * 14
        times = [round(i * 0.5, 3) for i in range(14)]
        win.flows.append(FlowRecord(
            timestamp=win.t_start + self.rng.uniform(0, WINDOW_SECONDS),
            src_ip=bot, dst_ip=c2,
            src_port=self.rng.randint(1024, 65535), dst_port=443,
            protocol="TCP", packet_count=14, byte_count=sum(lengths),
            duration=7.0, packet_lengths=lengths, packet_times=times,
            syn_count=1, ja4=self.rng.choice(MALICIOUS_JA4_POOL),
        ))
        win.ground_truth.append(InjectedEvent(win.window_id, "malware_in_encrypted_sessions", bot, c2,
                                               "rhythmic fixed-size TLS session, known-bad JA4"))

    def _inject_recon(self, win: SimulationWindow):
        attacker = self.attacker_ip
        victim_base = self.kill_chain_victim.rsplit(".", 1)[0]
        n_targets = self.rng.randint(60, 150)
        for _ in range(n_targets):
            win.flows.append(FlowRecord(
                timestamp=win.t_start + self.rng.uniform(0, WINDOW_SECONDS),
                src_ip=attacker, dst_ip=f"{victim_base}.{self.rng.randint(2,254)}",
                src_port=self.rng.randint(1024, 65535), dst_port=self.rng.choice([22, 23, 80, 443, 3389, 8080]),
                protocol="TCP", packet_count=1, byte_count=60, duration=0.01,
                packet_lengths=[60], packet_times=[0.0], syn_count=1,
            ))
        win.ground_truth.append(InjectedEvent(win.window_id, "reconnaissance_port_scanning",
                                               attacker, f"{victim_base}.0/24", f"fan-out to {n_targets} host:port pairs"))
        self._kill_chain_stage = max(self._kill_chain_stage, 1)

    def _inject_c2_beacon(self, win: SimulationWindow):
        # single steady beacon this window, part of the ongoing kill chain
        win.flows.append(FlowRecord(
            timestamp=win.t_start + 1.0,
            src_ip=self.kill_chain_victim, dst_ip=self.attacker_ip,
            src_port=self.rng.randint(1024, 65535), dst_port=443,
            protocol="TCP", packet_count=6, byte_count=1800, duration=1.0,
            packet_lengths=[300] * 6, packet_times=[i * 0.16 for i in range(6)],
            syn_count=1, ja4=self.rng.choice(MALICIOUS_JA4_POOL),
        ))
        win.ground_truth.append(InjectedEvent(win.window_id, "botnet_c2_beaconing",
                                               self.kill_chain_victim, self.attacker_ip, "periodic beacon"))
        self._kill_chain_stage = max(self._kill_chain_stage, 2)

    def _inject_exfiltration(self, win: SimulationWindow):
        victim = self.kill_chain_victim
        win.flows.append(FlowRecord(
            timestamp=win.t_start + self.rng.uniform(0, WINDOW_SECONDS),
            src_ip=victim, dst_ip=self.attacker_ip,
            src_port=self.rng.randint(1024, 65535), dst_port=443,
            protocol="TCP", packet_count=900, byte_count=self.rng.randint(8_000_000, 25_000_000),
            duration=30.0, packet_lengths=[1460] * 20,
            packet_times=[i * 0.02 for i in range(20)], syn_count=1,
        ))
        win.ground_truth.append(InjectedEvent(win.window_id, "data_exfiltration", victim, self.attacker_ip,
                                               "large asymmetric outbound transfer"))
        self._kill_chain_stage = max(self._kill_chain_stage, 3)

    # -- standalone single-attack demo injectors ----------------------------
    # Separate actors from the kill-chain ones above, so clicking "DDoS only"
    # (etc.) never accidentally lights up the kill-chain correlation banner.

    def _inject_c2_beacon_standalone(self, win: SimulationWindow):
        """One regular beacon per window between a dedicated demo bot/C2 pair.
        After ~4 windows the detector's rolling history has enough regular
        contacts to score high periodicity and fire.

        Deliberately shaped to be caught by the Botnet-C2 detector ONLY:
        a non-443 port and a benign JA4 (plus slight packet-size jitter)
        keep it out of the Encrypted-Malware detector's JA4-blocklist and
        fixed-buffer/rhythmic-SPLT triggers, so a "Botnet C2 only" demo
        doesn't also light up Malware in Encrypted Sessions."""
        jitter = self.rng.uniform(-0.3, 0.3)
        lengths = [300 + self.rng.randint(-20, 20) for _ in range(6)]
        win.flows.append(FlowRecord(
            timestamp=win.t_start + 1.0 + jitter,
            src_ip=self.demo_c2_bot_ip, dst_ip=self.demo_c2_server_ip,
            src_port=self.rng.randint(1024, 65535), dst_port=8443,
            protocol="TCP", packet_count=6, byte_count=sum(lengths), duration=1.0,
            packet_lengths=lengths, packet_times=[i * 0.16 for i in range(6)],
            syn_count=1, ja4=self.rng.choice(BENIGN_JA4_POOL),
        ))
        win.ground_truth.append(InjectedEvent(win.window_id, "botnet_c2_beaconing",
                                               self.demo_c2_bot_ip, self.demo_c2_server_ip,
                                               "standalone periodic beacon demo"))

    def _inject_recon_standalone(self, win: SimulationWindow):
        victim_base = self.demo_recon_victim_base
        n_targets = self.rng.randint(60, 150)
        for _ in range(n_targets):
            win.flows.append(FlowRecord(
                timestamp=win.t_start + self.rng.uniform(0, WINDOW_SECONDS),
                src_ip=self.demo_recon_attacker, dst_ip=f"{victim_base}.{self.rng.randint(2,254)}",
                src_port=self.rng.randint(1024, 65535), dst_port=self.rng.choice([22, 23, 80, 443, 3389, 8080]),
                protocol="TCP", packet_count=1, byte_count=60, duration=0.01,
                packet_lengths=[60], packet_times=[0.0], syn_count=1,
            ))
        win.ground_truth.append(InjectedEvent(win.window_id, "reconnaissance_port_scanning",
                                               self.demo_recon_attacker, f"{victim_base}.0/24",
                                               f"standalone scan demo, fan-out to {n_targets} host:port pairs"))

    def _inject_exfiltration_standalone(self, win: SimulationWindow):
        """Same large-outbound-transfer shape as the kill-chain exfil stage,
        but with light size/timing jitter (a real bulk transfer isn't
        perfectly uniform) so it doesn't also read as the Encrypted-Malware
        detector's fixed-buffer/rhythmic-beacon signature."""
        victim = self.demo_exfil_victim
        lengths = [1460 - self.rng.randint(0, 60) for _ in range(20)]
        times = [round(i * 0.02 + self.rng.uniform(0, 0.01), 4) for i in range(20)]
        win.flows.append(FlowRecord(
            timestamp=win.t_start + self.rng.uniform(0, WINDOW_SECONDS),
            src_ip=victim, dst_ip=self.demo_exfil_attacker,
            src_port=self.rng.randint(1024, 65535), dst_port=443,
            protocol="TCP", packet_count=900, byte_count=self.rng.randint(8_000_000, 25_000_000),
            duration=30.0, packet_lengths=lengths,
            packet_times=times, syn_count=1,
        ))
        win.ground_truth.append(InjectedEvent(win.window_id, "data_exfiltration",
                                               victim, self.demo_exfil_attacker,
                                               "standalone exfiltration demo"))

    # -- persistent low-rate botnet beaconing (background, separate bot) ----

    def _maybe_background_beacon(self, win: SimulationWindow):
        now = win.t_start
        if self.c2_last_beacon is None or (now - self.c2_last_beacon) >= self.c2_interval:
            jitter = self.rng.uniform(-2, 2)
            win.flows.append(FlowRecord(
                timestamp=now + max(0, jitter),
                src_ip=self.c2_bot_ip, dst_ip=self.c2_server_ip,
                src_port=self.rng.randint(1024, 65535), dst_port=443,
                protocol="TCP", packet_count=5, byte_count=1500, duration=0.8,
                packet_lengths=[300] * 5, packet_times=[i * 0.15 for i in range(5)],
                syn_count=1, ja4=self.rng.choice(MALICIOUS_JA4_POOL),
            ))
            self.c2_last_beacon = now

    # -- public streaming interface ------------------------------------------

    def stream(self, n_windows: int) -> Iterator[SimulationWindow]:
        for w in range(n_windows):
            t_start = self.t0 + w * WINDOW_SECONDS
            win = SimulationWindow(window_id=w, t_start=t_start, t_end=t_start + WINDOW_SECONDS)
            win.flows.extend(self._benign_flows(t_start))
            win.dns.extend(self._benign_dns(t_start))
            self._maybe_background_beacon(win)

            # independent, randomly-timed injections
            if self.rng.random() < 0.12:
                self._inject_ddos(win)
            if self.rng.random() < 0.12:
                self._inject_dga(win)
            if self.rng.random() < 0.12:
                self._inject_encrypted_malware(win)

            # the scripted multi-stage kill chain (recon -> beacon x N -> exfil)
            if w == self.kill_chain_start_window:
                self._inject_recon(win)
            elif self._kill_chain_stage == 1 and w in (self.kill_chain_start_window + 1, self.kill_chain_start_window + 2):
                self._inject_c2_beacon(win)
            elif self._kill_chain_stage == 2 and w == self.kill_chain_start_window + 3:
                self._inject_exfiltration(win)

            yield win

    def stream_scenario(self, scenario: str, n_windows: int = 12) -> Iterator[SimulationWindow]:
        """Deterministic, single-scenario streaming for the dashboard's demo
        buttons — one attack type (or all of them, or the full kill chain)
        injected on a fixed schedule, on top of ordinary benign background
        traffic. Unlike `stream()`, nothing here is left to random chance,
        so every button reliably produces the alert(s) it promises."""
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario '{scenario}'. Options: {list(SCENARIOS)}")

        for w in range(n_windows):
            t_start = self.t0 + w * WINDOW_SECONDS
            win = SimulationWindow(window_id=w, t_start=t_start, t_end=t_start + WINDOW_SECONDS)
            win.flows.extend(self._benign_flows(t_start))
            win.dns.extend(self._benign_dns(t_start))

            if scenario == "ddos":
                self._inject_ddos(win)

            elif scenario == "botnet_c2":
                self._inject_c2_beacon_standalone(win)

            elif scenario == "dga_dns":
                self._inject_dga(win)

            elif scenario == "encrypted_malware":
                self._inject_encrypted_malware(win)

            elif scenario == "recon_scan":
                self._inject_recon_standalone(win)

            elif scenario == "exfiltration":
                self._inject_exfiltration_standalone(win)

            elif scenario == "kill_chain":
                if w == 1:
                    self._inject_recon(win)
                elif self._kill_chain_stage == 1 and w in (2, 3):
                    self._inject_c2_beacon(win)
                elif self._kill_chain_stage == 2 and w == 4:
                    self._inject_exfiltration(win)

            elif scenario == "all":
                # the six independent detectors, each fed its own attack every window
                self._inject_ddos(win)
                self._inject_dga(win)
                self._inject_encrypted_malware(win)
                self._inject_c2_beacon_standalone(win)
                # plus the scripted kill chain running in parallel, so the
                # correlation engine also has something to fuse
                if w == 1:
                    self._inject_recon(win)
                elif self._kill_chain_stage == 1 and w in (2, 3):
                    self._inject_c2_beacon(win)
                elif self._kill_chain_stage == 2 and w == 4:
                    self._inject_exfiltration(win)

            yield win
