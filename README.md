# 🛡️ KAVACH — AI-Based Cyber Threat Detection for Unidirectional Traffic

**Team ByteBots · Smart India Hackathon 2026 · Problem Statement SIH26145**

KAVACH detects cyber threats in **unidirectional (data-diode / passive-mirror) IP traffic**, where the monitor can only *listen* and never talk back. It runs **six lightweight, parallel detectors** and a **rule-based correlation engine** that links weak signals into a single kill-chain alert, all shown on a live Streamlit dashboard.

> **Note:** This is a working demo pipeline. It uses a **synthetic traffic generator** (no real PCAP or dataset was available). Every detector runs a real algorithm on real feature vectors, not canned output. 

---

## ✨ Features

- **6 threat detectors** running in parallel, each with a different algorithm
- **Correlation engine** that turns *recon → C2 → exfiltration* into one `CRITICAL` kill-chain alert
- **Live Streamlit dashboard** with scenario demos and continuous mixed-traffic mode
- **Graceful degradation:** if one detector crashes, the other five keep running
- **Standard alert format:** all detectors emit the same JSON-style `Alert` schema
- **No payload inspection:** encrypted traffic is analysed using metadata only (JA4 + packet length/timing)
- **Zero infrastructure:** no Kafka, database or Docker needed

---

## 🚀 Quickstart

**Requirements:** Python 3.9+

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/kavach.git
cd kavach

# 2. (Recommended) create a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the dashboard
streamlit run dashboard/app.py
```

Open the URL Streamlit prints (usually <http://localhost:8501>).

### Using the dashboard

1. **Choose what to simulate**
   - *Scenario demo*: fire one attack type (or all) on demand
   - *Continuous*: benign traffic mixed with randomly timed attacks
2. **Set simulation length** (in 5-second windows), random seed and playback speed
3. Click **Start**. Alerts appear live as traffic streams in.
4. Pick the **Full Kill Chain** scenario to see recon → C2 beacon → exfiltration from one attacker IP escalate into a single kill-chain alert.

### Headless test (no UI)

```bash
python tests/test_pipeline.py
```

Runs 40 windows, prints a summary, and asserts that all 6 detector classes and the kill-chain alert fire.

---

## 🏗️ Architecture

```
TrafficGenerator (synthetic PCAP / flow windows)
        │
        ▼
 SimulationWindow { flows: FlowRecord[], dns: DNSRecord[] }
        │   fan-out to 6 parallel detectors
 ┌──────┬────────┬────────┬───────────┬────────┬─────────────┐
 ▼      ▼        ▼        ▼           ▼        ▼
DDoS  Botnet   DGA/DNS  Encrypted   Recon/   Exfiltration
      C2                Malware     Port Scan
 └──────┴────────┴────────┴───────────┴────────┴─────────────┘
                         │
                         ▼
            Standardized Alert (common/schema.py)
                         │
                         ▼
        Correlation Engine (rule-based, 60 s window)
                         │
                         ▼
              Streamlit live dashboard
```

---

## 🔍 Detectors

| # | File | Threat class | Signal | Method |
|---|------|--------------|--------|--------|
| 1 | `detectors/ddos.py` | Volumetric / Protocol DDoS | packets/sec per destination, SYN ratio, source-IP entropy | EWMA baseline + CUSUM change-point detection |
| 2 | `detectors/botnet_c2.py` | Botnet C2 beaconing | inter-arrival time regularity per (src, dst) pair | Coefficient of variation + FFT periodicity score |
| 3 | `detectors/dga_dns.py` | DGA / DNS tunnelling | domain entropy, n-gram likelihood, query shape | Shannon entropy + bigram language model |
| 4 | `detectors/encrypted_malware.py` | Malware in encrypted sessions | JA4 fingerprint + SPLT (packet length/timing sequence) | JA4 blocklist ∪ Random Forest, no decryption |
| 5 | `detectors/recon_scan.py` | Reconnaissance / port scanning | fan-out ratio (unique dst IP:port per source) | Threshold + normalized entropy scoring |
| 6 | `detectors/exfiltration.py` | Data exfiltration | byte-ratio asymmetry, throughput, packet-size composite | Isolation Forest on benign transfer shapes |

### Correlation engine

`correlation/engine.py` is deliberately **rule-based, not ML**, so it stays simple and reliable. It keeps a rolling 60-second window of alerts. If any 2 of {recon scan, C2 beacon, exfiltration} share a source or destination IP within that window, it emits a `CRITICAL` **`correlated_kill_chain`** alert:

```
reconnaissance_port_scanning → botnet_c2_beaconing → data_exfiltration
```

---

## 📁 Project Structure

```
kavach/
├── common/
│   └── schema.py                 # FlowRecord, DNSRecord, Alert data contracts
├── simulation/
│   └── traffic_generator.py      # Synthetic benign + attack traffic
├── detectors/
│   ├── base.py                   # BaseDetector + safe_process() wrapper
│   ├── ddos.py
│   ├── botnet_c2.py
│   ├── dga_dns.py
│   ├── encrypted_malware.py
│   ├── recon_scan.py
│   └── exfiltration.py
├── correlation/
│   └── engine.py                 # Rule-based kill-chain correlation
├── pipeline/
│   └── orchestrator.py           # Generator → detectors → correlation
├── dashboard/
│   └── app.py                    # Streamlit live UI
├── tests/
│   └── test_pipeline.py          # Headless smoke test
├── requirements.txt
└── README.md
```

---

## 🔌 Going from Demo to Real Traffic

Only `simulation/traffic_generator.py` needs to change. Everything downstream consumes `SimulationWindow` objects built from `FlowRecord` / `DNSRecord`, so a real ingestion module just has to produce the same shapes from:

- **PCAP** via Scapy or PyShark (raw capture from a passive tap)
- **Flow exports** (NetFlow / IPFIX / sFlow) via a Zeek or Suricata pipeline
- **DNS logs** via Zeek's `dns.log` for the DGA / tunnelling detector

The demo runs in-process instead of using Kafka/Redpanda. To add a real broker, make the orchestrator consume from a topic instead of a Python generator. The detector and correlation code stay the same.

---

## 🧰 Tech Stack

Python · NumPy · SciPy · scikit-learn · pandas · Streamlit · Altair

---
## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Contributors

- **Cheshta Khurana**
- **Raghav Tayal**

## 📞 Contact

For questions or support, please open an issue on GitHub.

---

**Note**: This project is for educational and privacy awareness purposes. Always review the code and understand what data is being collected before using any privacy tool.


