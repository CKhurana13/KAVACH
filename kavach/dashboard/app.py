from __future__ import annotations

import csv
import io
import itertools
import json
import os
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone

import altair as alt
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.schema import ThreatClass, Confidence
from pipeline.orchestrator import KavachPipeline
from simulation.traffic_generator import SCENARIOS

st.set_page_config(page_title="KAVACH | ByteBots", layout="wide", page_icon=None)

# ---------------------------------------------------------------- labels ---

THREAT_LABELS = {
    ThreatClass.DDOS: "Volumetric/Protocol DDoS",
    ThreatClass.BOTNET_C2: "Botnet C2 Beaconing",
    ThreatClass.DGA_DNS: "DGA/DNS Tunnelling",
    ThreatClass.ENCRYPTED_MALWARE: "Malware in Encrypted Sessions",
    ThreatClass.RECON_SCAN: "Reconnaissance/Port Scanning",
    ThreatClass.EXFILTRATION: "Data Exfiltration",
    ThreatClass.KILL_CHAIN: "Correlated Kill-Chain",
}

THREAT_ICONS = {
    ThreatClass.DDOS: "",
    ThreatClass.BOTNET_C2: "",
    ThreatClass.DGA_DNS: "",
    ThreatClass.ENCRYPTED_MALWARE: "",
    ThreatClass.RECON_SCAN: "",
    ThreatClass.EXFILTRATION: "",
    ThreatClass.KILL_CHAIN: "",
}

# one consistent accent color per threat class, used across the bar chart,
# alert table, and guide tab so the same attack always reads the same color.
# Kept to a single, formal navy/blue-gray family (light -> dark) instead of a
# multi-hue palette, so the UI stays plain and legible.
THREAT_COLORS = {
    ThreatClass.DDOS: "#7a8ca3",
    ThreatClass.BOTNET_C2: "#5f7590",
    ThreatClass.DGA_DNS: "#4a5f7a",
    ThreatClass.ENCRYPTED_MALWARE: "#3a4d66",
    ThreatClass.RECON_SCAN: "#8a97a8",
    ThreatClass.EXFILTRATION: "#2c3e52",
    ThreatClass.KILL_CHAIN: "#8c1c24",
}

# one-line, plain-English explanation of each detector — shown in the guide
# tab, so a judge doesn't need the deck to follow along
THREAT_BLURBS = {
    ThreatClass.DDOS: "Sudden flood of tiny connections from many source IPs at one destination.",
    ThreatClass.BOTNET_C2: "A host 'checking in' with the same remote server on a suspiciously regular clock.",
    ThreatClass.DGA_DNS: "A host querying a burst of random-looking, auto-generated domain names.",
    ThreatClass.ENCRYPTED_MALWARE: "A TLS session shaped like a bot, not a browser — fixed-size packets, robotic timing.",
    ThreatClass.RECON_SCAN: "One source probing dozens of host:port combinations in a short window.",
    ThreatClass.EXFILTRATION: "An unusually large, sustained outbound transfer to an external IP.",
    ThreatClass.KILL_CHAIN: "Recon, C2 and exfiltration alerts sharing an actor within 60s — chained into one alert.",
}

# Scenario picker: human label + which threat classes it's expected to light up
SCENARIO_INFO = {
    "ddos":               {"label": "DDoS only",               "classes": [ThreatClass.DDOS]},
    "botnet_c2":          {"label": "Botnet C2 only",           "classes": [ThreatClass.BOTNET_C2]},
    "dga_dns":            {"label": "DGA/DNS Tunnelling only",  "classes": [ThreatClass.DGA_DNS]},
    "encrypted_malware":  {"label": "Encrypted Malware only",   "classes": [ThreatClass.ENCRYPTED_MALWARE]},
    "recon_scan":         {"label": "Recon/Port Scan only",     "classes": [ThreatClass.RECON_SCAN]},
    "exfiltration":       {"label": "Data Exfiltration only",   "classes": [ThreatClass.EXFILTRATION]},
    "kill_chain":         {"label": "Full kill chain (recon -> C2 -> exfil)",
                            "classes": [ThreatClass.RECON_SCAN, ThreatClass.BOTNET_C2, ThreatClass.EXFILTRATION, ThreatClass.KILL_CHAIN]},
    "all":                {"label": "All 6 attacks simultaneously",
                            "classes": list(THREAT_LABELS.keys())},
}
assert set(SCENARIO_INFO) == set(SCENARIOS)

# inherent danger of the attack *type* — independent of how confident the
# detector is about this particular alert. A LOW-confidence exfiltration
# alert is still HIGH risk if it turns out to be real.
RISK_LEVELS = {
    ThreatClass.DDOS: "high",
    ThreatClass.BOTNET_C2: "high",
    ThreatClass.DGA_DNS: "medium",
    ThreatClass.ENCRYPTED_MALWARE: "high",
    ThreatClass.RECON_SCAN: "low",
    ThreatClass.EXFILTRATION: "critical",
    ThreatClass.KILL_CHAIN: "critical",
}

RISK_ORDER = ["low", "medium", "high", "critical"]


def compute_alert_risk(alert, kill_chain_actors: set[str]) -> str:
    """Per-alert risk, not just per-attack-type risk.

    Starts from the attack type's inherent danger (RISK_LEVELS above), then
    adjusts for THIS specific alert the way a real analyst would triage it:
      - a HIGH-confidence detection is treated as more dangerous than a LOW-
        confidence one of the same type (stronger signal the threat is real)
      - if the source IP is already implicated in a correlated kill-chain
        elsewhere in this run, every other alert from that same actor gets
        escalated — you don't treat a scan from a known-active attacker the
        same as a scan from a first-time source.
    Kill-chain alerts themselves are left at their inherent "critical" floor.
    """
    if alert.threat_class == ThreatClass.KILL_CHAIN:
        return RISK_LEVELS[alert.threat_class]

    idx = RISK_ORDER.index(RISK_LEVELS[alert.threat_class])
    if alert.confidence == Confidence.HIGH:
        idx += 1
    elif alert.confidence == Confidence.LOW:
        idx -= 1
    if alert.src_ip in kill_chain_actors:
        idx += 1
    idx = max(0, min(idx, len(RISK_ORDER) - 1))
    return RISK_ORDER[idx]


CONF_COLOR = {
    Confidence.LOW.value: "#9aa3af",
    Confidence.MEDIUM.value: "#5b7ea3",
    Confidence.HIGH.value: "#2c4a6e",
    Confidence.CRITICAL.value: "#8c1c24",
}

CUSTOM_CSS = """
<style>
.stApp { background-color: #ffffff; }
.block-container {padding-top: 1.4rem; max-width: 1400px;}

body, .stApp, p, div, span, label { color: #1f2328; }

div[data-testid="stMetric"] {
    background: #f7f8fa;
    border: 1px solid #d5d9de; border-radius: 8px;
    padding: 16px 18px;
}
div[data-testid="stMetricLabel"] { color: #4b5461; font-size: 0.78rem; letter-spacing: 0.02em; text-transform: uppercase; }
div[data-testid="stMetricValue"] { font-weight: 700; color: #1f2328; }

.kc-banner {
    background: #faf1f1;
    border: 1px solid #8c1c24; border-radius: 6px; padding: 14px 18px;
    margin-bottom: 12px; color: #6e1015; font-size: 0.95rem;
}
.mode-banner {
    background: #f2f4f6; border: 1px solid #d5d9de; border-radius: 6px;
    padding: 10px 16px; margin-bottom: 14px; color: #33383f; font-size: 0.9rem;
}
.pill {
    border-radius: 4px; padding: 3px 11px; font-size: 0.72rem; font-weight: 700;
    color: white; display: inline-block; letter-spacing: 0.02em;
}
.legend-pill { margin-right: 8px; margin-bottom: 4px; }

.section-title {
    font-size: 1.05rem; font-weight: 700; margin: 4px 0 10px 0; color: #1f2328;
    display: flex; align-items: center; gap: 8px;
}
.section-sub { color: #545b66; font-size: 0.82rem; margin: -6px 0 12px 0; }

.threat-card {
    background: #f7f8fa; border: 1px solid #d5d9de; border-left: 4px solid var(--accent, #5b7ea3);
    border-radius: 6px; padding: 12px 16px; margin-bottom: 10px;
}
.threat-card b { color: #1f2328; }
.threat-card .blurb { color: #4b5461; font-size: 0.88rem; margin-top: 2px; }

.kc-card {
    background: #f7f8fa; border: 1px solid #d5d9de; border-radius: 6px;
    padding: 12px 14px; margin-bottom: 8px;
}
.kc-card code { color: #1f2328; }

div[data-testid="stDataFrame"] { border-radius: 8px; overflow: hidden; border: 1px solid #d5d9de; }
hr { border-color: #d5d9de; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def section_header(title: str, sub: str = ""):
    st.markdown(f"<div class='section-title'>{title}</div>", unsafe_allow_html=True)
    if sub:
        st.markdown(f"<div class='section-sub'>{sub}</div>", unsafe_allow_html=True)


# ---------------------------------------------------------------- state ----

if "pipeline" not in st.session_state:
    st.session_state.pipeline = None
    st.session_state.window_iter = None
    st.session_state.results = []
    st.session_state.running = False
    st.session_state.windows_done = 0
    st.session_state.mode_label = None

# ---------------------------------------------------------------- sidebar --

with st.sidebar:
    st.markdown("### KAVACH")
    st.caption("AI-based detection of cyber threats in unidirectional IP traffic — ByteBots, SIH26145")
    st.divider()

    st.markdown("**1. Choose what to simulate**")
    run_mode = st.radio(
        "Simulation mode",
        options=["Continuous (mixed, realistic)", "Scenario demo (pick one)"],
        index=1,
        label_visibility="collapsed",
        help="Continuous mode mixes benign traffic with randomly-timed attacks over a long run. "
             "Scenario mode deterministically fires one chosen attack (or all of them) so you can "
             "demo a specific detector on demand.",
    )

    scenario_key = None
    if run_mode.startswith("Scenario"):
        scenario_key = st.selectbox(
            "Which attack?",
            options=list(SCENARIO_INFO.keys()),
            format_func=lambda k: SCENARIO_INFO[k]["label"],
            index=0,
        )
        expected = SCENARIO_INFO[scenario_key]["classes"]
        chip_htmls = []
        for c in expected:
            accent = THREAT_COLORS.get(c, "#555")
            chip_htmls.append(
                f"<span class='pill legend-pill' style='background:{accent}'>"
                f"{THREAT_LABELS[c]}</span>"
            )
        chips = " ".join(chip_htmls)
        st.markdown(f"<div class='section-sub'>Expected to trigger:</div>{chips}", unsafe_allow_html=True)
        default_windows = 10
    else:
        default_windows = 40

    st.markdown("**2. Simulation settings**")
    n_windows = st.slider("Length (5s windows)", 6, 80, default_windows)
    seed = st.number_input("Random seed", value=123, step=1)
    speed = st.select_slider("Playback speed", options=["Slow", "Normal", "Fast", "Instant"], value="Normal")
    speed_delay = {"Slow": 0.5, "Normal": 0.2, "Fast": 0.05, "Instant": 0.0}[speed]

    st.markdown("**3. Run**")
    col_a, col_b = st.columns(2)
    start = col_a.button("Start", width='stretch', type="primary")
    reset = col_b.button("Reset", width='stretch')

    st.divider()
    st.markdown("**Read-only, passive design**")
    st.caption("No probes, no handshakes, no return-path commands — mirrors a data-diode / passive-mirror deployment.")
    st.markdown("**Tech stack**")
    st.caption("Python · Scapy/PyShark · Kafka/Redpanda (prod) · pandas · scikit-learn · Streamlit")

if reset:
    st.session_state.pipeline = None
    st.session_state.window_iter = None
    st.session_state.results = []
    st.session_state.running = False
    st.session_state.windows_done = 0
    st.session_state.mode_label = None
    st.rerun()

if start:
    st.session_state.pipeline = KavachPipeline(seed=int(seed), kill_chain_start_window=1)
    if scenario_key:
        st.session_state.window_iter = st.session_state.pipeline.stream_scenario(scenario_key, n_windows)
        st.session_state.mode_label = SCENARIO_INFO[scenario_key]["label"]
    else:
        st.session_state.window_iter = st.session_state.pipeline.stream(n_windows)
        st.session_state.mode_label = "Continuous (mixed, realistic) traffic"
    st.session_state.results = []
    st.session_state.running = True
    st.session_state.windows_done = 0

# ---------------------------------------------------------------- header ---

st.title("KAVACH — Live Detection Dashboard")
st.caption("Six parallel, read-only detectors + a correlation engine, watching a simulated passive-mirror feed. "
           "Real deployment ingests PCAP / NetFlow-IPFIX-sFlow off a data-diode tap.")

if st.session_state.mode_label:
    st.markdown(f"<div class='mode-banner'>Currently running: <b>{st.session_state.mode_label}</b></div>",
                unsafe_allow_html=True)

tab_live, tab_guide = st.tabs(["Live Dashboard", "Attack & Detector Guide"])

with tab_live:
    kc_placeholder = st.empty()
    kpi_placeholder = st.empty()
    export_placeholder = st.empty()
    legend_placeholder = st.empty()
    body_placeholder = st.empty()
    truth_placeholder = st.empty()

# ------------------------------------------------------------- rendering ---

def _confidence_bg(val: str) -> str:
    return f"background-color: {CONF_COLOR.get(val.lower(), '#333')}; color: white; font-weight: 600; " \
           f"border-radius: 6px; text-align: center;"


# --------------------------------------------------------- data export -----
# "Save data" support: bundles everything the dashboard has reported so far
# (detector alerts, kill-chain alerts, ground truth) into files the user can
# download and keep for later reference/analysis, without touching the rest
# of the app's behavior.

def build_export_bundle(results, mode_label, seed_value, windows_target) -> dict:
    all_alerts = [a for r in results for a in r.detector_alerts]
    all_kc = [a for r in results for a in r.kill_chain_alerts]
    all_truth = [gt for r in results for gt in r.window.ground_truth]
    kill_chain_actors = {kc.src_ip for kc in all_kc}

    return {
        "export_generated_at": datetime.now(timezone.utc).isoformat(),
        "run": {
            "mode": mode_label,
            "seed": seed_value,
            "windows_target": windows_target,
            "windows_processed": len(results),
        },
        "summary": {
            "total_flows_ingested": sum(r.flows_processed for r in results),
            "total_dns_ingested": sum(r.dns_processed for r in results),
            "total_detector_alerts": len(all_alerts),
            "total_kill_chain_alerts": len(all_kc),
        },
        "detector_alerts": [
            {
                **a.to_dict(),
                "threat_label": THREAT_LABELS.get(a.threat_class, a.threat_class.value),
                "risk": compute_alert_risk(a, kill_chain_actors),
            }
            for a in sorted(all_alerts, key=lambda x: x.timestamp)
        ],
        "kill_chain_alerts": [a.to_dict() for a in sorted(all_kc, key=lambda x: x.timestamp)],
        "ground_truth": [asdict(gt) for gt in all_truth],
    }


def export_bundle_to_json(bundle: dict) -> bytes:
    return json.dumps(bundle, indent=2, default=str).encode("utf-8")


def export_bundle_to_csv(bundle: dict) -> bytes:
    """Flattened alert log (detector + kill-chain alerts) as CSV, for
    spreadsheets. `evidence`/`flow_ids` are serialized to JSON text per cell."""
    buf = io.StringIO()
    fieldnames = [
        "record_type", "time_utc", "threat_class", "threat_label", "detector",
        "confidence", "risk", "score", "src_ip", "dst_ip", "alert_id",
        "flow_ids", "evidence",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()

    for a in bundle["detector_alerts"]:
        writer.writerow({
            "record_type": "detector_alert",
            "time_utc": datetime.fromtimestamp(a["timestamp"], tz=timezone.utc).isoformat(),
            "threat_class": a["threat_class"],
            "threat_label": a["threat_label"],
            "detector": a["detector"],
            "confidence": a["confidence"],
            "risk": a["risk"],
            "score": a["score"],
            "src_ip": a["src_ip"],
            "dst_ip": a["dst_ip"],
            "alert_id": a["alert_id"],
            "flow_ids": json.dumps(a["flow_ids"]),
            "evidence": json.dumps(a["evidence"]),
        })

    for kc in bundle["kill_chain_alerts"]:
        writer.writerow({
            "record_type": "kill_chain_alert",
            "time_utc": datetime.fromtimestamp(kc["timestamp"], tz=timezone.utc).isoformat(),
            "threat_class": kc["threat_class"],
            "threat_label": THREAT_LABELS.get(ThreatClass.KILL_CHAIN, "Correlated Kill-Chain"),
            "detector": kc["detector"],
            "confidence": kc["confidence"],
            "risk": "critical",
            "score": kc["score"],
            "src_ip": kc["src_ip"],
            "dst_ip": kc["dst_ip"],
            "alert_id": kc["alert_id"],
            "flow_ids": json.dumps(kc["flow_ids"]),
            "evidence": json.dumps(kc["evidence"]),
        })

    return buf.getvalue().encode("utf-8")


# render() can be called several times within a single script run while a
# simulation streams in (plus once more after the loop finishes with the same
# final results), so widget keys can't be derived from the data itself — use
# a call counter, fresh on every script run, to keep each key unique.
_render_call_counter = itertools.count()


def render(results, windows_target: int):
    render_call_id = next(_render_call_counter)
    all_alerts = [a for r in results for a in r.detector_alerts]
    all_kc = [a for r in results for a in r.kill_chain_alerts]
    all_truth = [gt for r in results for gt in r.window.ground_truth]
    total_flows = sum(r.flows_processed for r in results)
    total_dns = sum(r.dns_processed for r in results)
    windows_done = len(results)

    if all_kc:
        latest_kc = all_kc[-1]
        kc_placeholder.markdown(
            f"<div class='kc-banner'><b>KILL-CHAIN ALERT</b> — actor <code>{latest_kc.src_ip}</code> linked "
            f"across stages: <b>{latest_kc.evidence['narrative'].replace('_', ' ')}</b> "
            f"&nbsp;|&nbsp; confidence: CRITICAL &nbsp;|&nbsp; combined score: {latest_kc.score}</div>",
            unsafe_allow_html=True,
        )
    else:
        kc_placeholder.empty()

    with kpi_placeholder.container():
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Windows processed", f"{windows_done}/{windows_target}")
        c2.metric("Flows ingested", f"{total_flows:,}")
        c3.metric("DNS records ingested", f"{total_dns:,}")
        c4.metric("Detector alerts", f"{len(all_alerts)}")
        c5.metric("Kill-chain escalations", f"{len(all_kc)}")

    with export_placeholder.container():
        section_header("Save reported data",
                        "Download everything reported so far — detector alerts, kill-chain "
                        "alerts, and ground truth — for later reference or analysis.")
        has_data = bool(all_alerts) or bool(all_kc) or bool(all_truth)
        bundle = build_export_bundle(
            results,
            mode_label=st.session_state.mode_label,
            seed_value=int(seed),
            windows_target=windows_target,
        )
        run_ts = time.strftime("%Y%m%d_%H%M%S")
        ec1, ec2 = st.columns(2)
        ec1.download_button(
            "Download full log (JSON)",
            data=export_bundle_to_json(bundle),
            file_name=f"kavach_log_{run_ts}.json",
            mime="application/json",
            width='stretch',
            disabled=not has_data,
            key=f"download_json_log_{render_call_id}",
            help="Everything reported so far: alerts, kill-chain alerts, ground truth, "
                 "and run summary, in one structured file.",
        )
        ec2.download_button(
            "Download alert log (CSV)",
            data=export_bundle_to_csv(bundle),
            file_name=f"kavach_alerts_{run_ts}.csv",
            mime="text/csv",
            width='stretch',
            disabled=not has_data,
            key=f"download_csv_log_{render_call_id}",
            help="Detector + kill-chain alerts flattened into one spreadsheet-friendly table.",
        )

    with legend_placeholder.container():
        conf_pills = "".join(
            f"<span class='pill legend-pill' style='background:{color}'>{label.upper()}</span>"
            for label, color in CONF_COLOR.items()
        )
        st.markdown(f"**Confidence** *(how sure the detector is)*: {conf_pills}", unsafe_allow_html=True)
        st.markdown(f"**Risk level** *(how dangerous this attack type is)*: {conf_pills}", unsafe_allow_html=True)

    with body_placeholder.container():
        left, right = st.columns([1.15, 1])

        with left:
            section_header("Alerts by threat class")
            counts = {tc: 0 for tc in ThreatClass if tc != ThreatClass.KILL_CHAIN}
            for a in all_alerts:
                if a.threat_class in counts:
                    counts[a.threat_class] += 1
            df_counts = pd.DataFrame({
                "threat_class": [THREAT_LABELS[tc] for tc in counts],
                "alerts": list(counts.values()),
                "color": [THREAT_COLORS[tc] for tc in counts],
            })
            chart = (
                alt.Chart(df_counts)
                .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
                .encode(
                    x=alt.X("threat_class:N", sort=None, title=None,
                            axis=alt.Axis(labelAngle=-35, labelColor="#aab1c0", labelLimit=160,
                                           labelOverlap=False, labelFontSize=11)),
                    y=alt.Y("alerts:Q", title="alerts", axis=alt.Axis(labelColor="#aab1c0")),
                    color=alt.Color("threat_class:N", scale=alt.Scale(
                        domain=[THREAT_LABELS[tc] for tc in counts],
                        range=[THREAT_COLORS[tc] for tc in counts]), legend=None),
                    tooltip=["threat_class", "alerts"],
                )
                .properties(height=290, padding={"bottom": 20})
                .configure_view(strokeWidth=0)
                .configure_axis(grid=True, gridColor="#20242e", domainColor="#2b3040")
            )
            st.altair_chart(chart, use_container_width=True)

            section_header("Live alert stream",
                            "Most recent first. score is the raw 0-1 detector signal behind the confidence tier. "
                            "Risk starts from the attack type's inherent danger, then rises with this alert's own "
                            "confidence and escalates further if the source IP is already tied to a kill-chain "
                            "elsewhere in the run. Confidence = how sure the detector is about this one alert.")
            if all_alerts:
                kill_chain_actors = {kc.src_ip for kc in all_kc}
                rows = []
                for a in sorted(all_alerts, key=lambda x: x.timestamp, reverse=True)[:25]:
                    rows.append({
                        "time": time.strftime("%H:%M:%S", time.localtime(a.timestamp)),
                        "attack": f"{THREAT_LABELS[a.threat_class]}",
                        "risk": compute_alert_risk(a, kill_chain_actors).upper(),
                        "confidence": a.confidence.value.upper(),
                        "score": a.score,
                        "src_ip": a.src_ip,
                        "dst_ip": a.dst_ip,
                        "detector": a.detector,
                    })
                df_alerts = pd.DataFrame(rows)
                styled = df_alerts.style.map(_confidence_bg, subset=["confidence", "risk"])
                st.dataframe(styled, width='stretch', height=380, hide_index=True)
            else:
                st.info("No alerts yet — waiting for traffic windows...")

        with right:
            section_header("Kill-chain narrative")
            if all_kc:
                for kc in all_kc[-5:][::-1]:
                    st.markdown(
                        f"<div class='kc-card'>"
                        f"<b>Actor:</b> <code>{kc.src_ip}</code><br>"
                        f"<b>Stages linked:</b> {kc.evidence['narrative'].replace('_', ' ')}<br>"
                        f"<b>Combined score:</b> {kc.score}<br>"
                        f"<span style='color:#8b93a6;font-size:0.8rem;'>Alert IDs: {', '.join(kc.evidence['stage_alert_ids'])}</span>"
                        f"</div>", unsafe_allow_html=True,
                    )
            else:
                st.caption("No multi-stage attacks correlated yet. The correlation engine links "
                           "recon → C2 → exfiltration alerts that share an IP within a 60s window.")

            section_header("Alert evidence (most recent)")
            if all_alerts:
                latest = sorted(all_alerts, key=lambda x: x.timestamp, reverse=True)[0]
                st.caption(f"Why **{THREAT_LABELS[latest.threat_class]}** fired, in the detector's own numbers:")
                st.json(latest.to_dict())
            else:
                st.caption("—")

    with truth_placeholder.container():
        with st.expander(f"Ground truth — what was actually injected ({len(all_truth)} events)", expanded=False):
            st.caption("For demo/judging purposes only — a real deployment has no ground-truth labels. "
                       "Compare this against the alert stream above to see detection working.")
            if all_truth:
                rows = [{
                    "window": gt.window,
                    "attack": THREAT_LABELS.get(ThreatClass(gt.threat_class), gt.threat_class),
                    "attacker": gt.attacker_ip,
                    "victim": gt.victim_ip,
                    "detail": gt.note,
                } for gt in all_truth]
                st.dataframe(pd.DataFrame(rows), width='stretch', height=220, hide_index=True)
            else:
                st.caption("Nothing injected yet.")

    st.session_state.results = results
    st.session_state.windows_done = windows_done


with tab_live:
    if st.session_state.pipeline is not None and st.session_state.running:
        results = []
        for result in st.session_state.window_iter:
            results.append(result)
            render(results, windows_target=n_windows)
            if speed_delay:
                time.sleep(speed_delay)
        st.session_state.running = False
        render(results, windows_target=n_windows)
        st.success("Simulation complete.")
    elif st.session_state.results:
        render(st.session_state.results, windows_target=n_windows)
    else:
        kpi_placeholder.info(
            "Pick a simulation mode in the sidebar. **Scenario demo** lets you fire one attack type "
            "at a time (or all six at once) to show a specific detector on demand — good for a live walkthrough. "
            "**Continuous** mixes everything randomly over a longer run, closer to real monitoring."
        )

# --------------------------------------------------------------- guide -----

with tab_guide:
    section_header("What each detector is watching for",
                    "Plain-language version of the six independent detectors, plus how the correlation "
                    "engine chains them into one kill-chain alert.")
    for tc in ThreatClass:
        color = THREAT_COLORS[tc]
        risk = RISK_LEVELS[tc]
        risk_color = CONF_COLOR[risk]
        st.markdown(
            f"<div class='threat-card' style='--accent:{color}'>"
            f"<b>{THREAT_LABELS[tc]}</b> "
            f"<span class='pill' style='background:{risk_color}'>{risk.upper()} RISK</span>"
            f"<div class='blurb'>{THREAT_BLURBS[tc]}</div>"
            f"</div>", unsafe_allow_html=True,
        )

    st.divider()
    section_header("How to read the Live Dashboard")
    st.markdown(
        "- **Confidence legend** (top of the live tab) — LOW/MEDIUM/HIGH/CRITICAL color-codes every alert; "
        "CRITICAL is reserved for kill-chain escalations.\n"
        "- **Alerts by threat class** — quick color-coded chart of which detectors have fired and how often.\n"
        "- **Live alert stream** — every individual detector alert, most recent first, confidence color-coded.\n"
        "- **Kill-chain narrative** — the correlation engine's fused, high-confidence alerts, with the "
        "underlying per-stage alert IDs it linked.\n"
        "- **Alert evidence** — the raw feature values behind the most recent alert (why it fired, not just that it did).\n"
        "- **Ground truth** — an expandable, judging-only panel showing exactly what was injected, "
        "so you can point at an attack and then point at the alert that caught it."
    )
