# Network Traffic Logger & Analyzer (Scapy)

Python project that captures live network packets, saves them to a `.pcap` file, and analyzes traffic for unusual volume spikes.

## Features
- Live packet capture with Scapy
- Save traffic to `.pcap`
- Offline analysis for existing `.pcap` files
- Spike detection for:
  - packets per time window
  - bytes per time window
- Top IP endpoints report
- Optional text report export

## Requirements
- Python 3.9+
- Scapy

Install dependency:

```bash
pip install scapy
```

## Usage

### 1) Live capture + analysis

```bash
python3 scapy.py --duration 60 --iface eth0 --output captures/live_capture.pcap
```

Options:
- `--duration`: capture time in seconds
- `--count`: stop after N packets
- `--iface`: interface (example: `eth0`, `wlan0`)
- `--filter`: BPF filter (example: `"tcp or udp"`)

### 2) Analyze an existing PCAP

```bash
python3 scapy.py --offline captures/live_capture.pcap
```

### 3) Save report to file

```bash
python3 scapy.py --offline captures/live_capture.pcap --report reports/analysis.txt
```

## Spike Detection Tuning
- `--interval`: time bucket size in seconds (default: `1.0`)
- `--lookback`: number of baseline windows (default: `20`)
- `--min-baseline`: minimum windows before detection starts (default: `5`)
- `--zscore`: z-score sensitivity (default: `3.0`)
- `--factor`: multiplicative threshold vs baseline (default: `2.0`)
- `--min-alert-packets`: minimum packets in a window to consider alerting (default: `20`)
- `--min-alert-bytes`: minimum bytes in a window to consider alerting (default: `20000`)

## Notes
- Live capture may require elevated privileges:
  - Linux/macOS: run with `sudo` if needed.
- If no packets are captured, the report states that explicitly.
