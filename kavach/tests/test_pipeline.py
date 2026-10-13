import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collections import Counter
from pipeline.orchestrator import KavachPipeline
from common.schema import ThreatClass
from simulation.traffic_generator import SCENARIOS


def main():
    pipeline = KavachPipeline(seed=123, kill_chain_start_window=6)
    n_windows = 40
    class_counts = Counter()
    kill_chain_count = 0
    total_flows = 0
    total_dns = 0

    for result in pipeline.stream(n_windows):
        total_flows += result.flows_processed
        total_dns += result.dns_processed
        for a in result.detector_alerts:
            class_counts[a.threat_class] += 1
        kill_chain_count += len(result.kill_chain_alerts)
        if result.kill_chain_alerts:
            for kc in result.kill_chain_alerts:
                print(f"[window {result.window.window_id}] KILL-CHAIN ALERT: "
                      f"actor={kc.src_ip} stages={kc.evidence['narrative']} score={kc.score}")

    print("\n=== Summary over", n_windows, "windows (continuous/mixed mode) ===")
    print("Total flows processed:", total_flows)
    print("Total DNS records processed:", total_dns)
    print("Per-class detector alert counts:")
    for tc in ThreatClass:
        print(f"  {tc.value:35s} {class_counts.get(tc, 0)}")
    print("Kill-chain alerts:", kill_chain_count)

    missing = [tc for tc in ThreatClass if tc != ThreatClass.KILL_CHAIN and class_counts.get(tc, 0) == 0]
    assert not missing, f"These threat classes were never detected: {missing}"
    assert kill_chain_count > 0, "Correlation engine never escalated a kill chain"
    print("\nALL 6 THREAT CLASSES DETECTED + KILL-CHAIN CORRELATION WORKING.")


# threat class each single-attack scenario is expected to trigger
SCENARIO_EXPECTED_CLASS = {
    "ddos": ThreatClass.DDOS,
    "botnet_c2": ThreatClass.BOTNET_C2,
    "dga_dns": ThreatClass.DGA_DNS,
    "encrypted_malware": ThreatClass.ENCRYPTED_MALWARE,
    "recon_scan": ThreatClass.RECON_SCAN,
    "exfiltration": ThreatClass.EXFILTRATION,
}


def test_scenarios():
    print("\n=== Testing each individual scenario button ===")
    for scenario in SCENARIO_EXPECTED_CLASS:
        pipeline = KavachPipeline(seed=7)
        class_counts = Counter()
        for result in pipeline.stream_scenario(scenario, n_windows=10):
            for a in result.detector_alerts:
                class_counts[a.threat_class] += 1
        expected = SCENARIO_EXPECTED_CLASS[scenario]
        got = class_counts.get(expected, 0)
        status = "OK" if got > 0 else "FAILED"
        print(f"  [{status}] scenario={scenario:20s} -> {expected.value:35s} alerts={got}")
        assert got > 0, f"Scenario '{scenario}' never triggered {expected.value}"

    # kill_chain scenario should escalate
    pipeline = KavachPipeline(seed=7)
    kc_count = 0
    for result in pipeline.stream_scenario("kill_chain", n_windows=10):
        kc_count += len(result.kill_chain_alerts)
    print(f"  [{'OK' if kc_count else 'FAILED'}] scenario=kill_chain          -> kill-chain escalations={kc_count}")
    assert kc_count > 0, "kill_chain scenario never escalated"

    # all scenario should trigger every threat class + kill chain
    pipeline = KavachPipeline(seed=7)
    class_counts = Counter()
    kc_count = 0
    for result in pipeline.stream_scenario("all", n_windows=10):
        for a in result.detector_alerts:
            class_counts[a.threat_class] += 1
        kc_count += len(result.kill_chain_alerts)
    missing = [tc for tc in ThreatClass if tc != ThreatClass.KILL_CHAIN and class_counts.get(tc, 0) == 0]
    status = "OK" if not missing and kc_count else "FAILED"
    print(f"  [{status}] scenario=all                  -> classes hit={len(ThreatClass) - 1 - len(missing)}/6, kill-chain={kc_count}")
    assert not missing, f"'all' scenario missed: {missing}"
    assert kc_count > 0, "'all' scenario never escalated a kill chain"

    print("\nALL 7 SCENARIO BUTTONS (6 individual + kill_chain) + 'ALL' MODE WORK.")

    assert set(SCENARIOS) == {"ddos", "botnet_c2", "dga_dns", "encrypted_malware",
                               "recon_scan", "exfiltration", "kill_chain", "all"}


if __name__ == "__main__":
    main()
    test_scenarios()
