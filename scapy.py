#!/usr/bin/env python3
"""Network Traffic Logger & Analyzer built with Scapy."""

import argparse
import math
import statistics
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# This file is named "scapy.py", which would shadow the real Scapy package.
# Remove local directory entries so `import scapy` resolves to site-packages.
_SCRIPT_DIR = str(Path(__file__).resolve().parent)
for _entry in ("", _SCRIPT_DIR):
    while _entry in sys.path:
        sys.path.remove(_entry)

SCAPY_IMPORT_ERROR = None
try:
    from scapy.all import IP, IPv6, PcapReader, PcapWriter, sniff
except ModuleNotFoundError as exc:
    SCAPY_IMPORT_ERROR = exc
    IP = None  # type: ignore[assignment]
    IPv6 = None  # type: ignore[assignment]
    PcapReader = None  # type: ignore[assignment]
    PcapWriter = None  # type: ignore[assignment]
    sniff = None  # type: ignore[assignment]


@dataclass
class WindowStat:
    start: float
    end: float
    packets: int
    bytes: int


@dataclass
class Spike:
    metric: str
    window: WindowStat
    baseline_mean: float
    baseline_std: float
    threshold: float
    ratio: float
    zscore: float


def format_bytes(num_bytes: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{num_bytes:.2f} B"


class TrafficAnalyzer:
    def __init__(
        self,
        interval: float = 1.0,
        lookback: int = 20,
        min_baseline_windows: int = 5,
        spike_zscore: float = 3.0,
        min_spike_factor: float = 2.0,
        min_alert_packets: int = 20,
        min_alert_bytes: int = 20_000,
    ) -> None:
        if interval <= 0:
            raise ValueError("interval must be > 0")
        if lookback < 1:
            raise ValueError("lookback must be >= 1")
        if min_baseline_windows < 2:
            raise ValueError("min_baseline_windows must be >= 2")

        self.interval = float(interval)
        self.lookback = int(lookback)
        self.min_baseline_windows = int(min_baseline_windows)
        self.spike_zscore = float(spike_zscore)
        self.min_spike_factor = float(min_spike_factor)
        self.min_alert_packets = int(min_alert_packets)
        self.min_alert_bytes = int(min_alert_bytes)

        self.total_packets = 0
        self.total_bytes = 0
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

        self.windows: List[WindowStat] = []
        self._current_start: Optional[float] = None
        self._current_packets = 0
        self._current_bytes = 0

        self.endpoint_stats: Dict[str, List[int]] = defaultdict(lambda: [0, 0])

    def observe(self, packet_time: float, packet_len: int, packet=None) -> None:
        ts = float(packet_time)
        size = int(packet_len)

        if self._current_start is None:
            # Align to interval boundaries for cleaner time buckets.
            self._current_start = math.floor(ts / self.interval) * self.interval
            self.first_ts = ts

        while ts >= self._current_start + self.interval:
            self.windows.append(
                WindowStat(
                    start=self._current_start,
                    end=self._current_start + self.interval,
                    packets=self._current_packets,
                    bytes=self._current_bytes,
                )
            )
            self._current_start += self.interval
            self._current_packets = 0
            self._current_bytes = 0

        self._current_packets += 1
        self._current_bytes += size
        self.total_packets += 1
        self.total_bytes += size
        self.last_ts = ts

        if packet is not None:
            self._track_endpoints(packet, size)

    def finalize(self) -> None:
        if self._current_start is None:
            return

        self.windows.append(
            WindowStat(
                start=self._current_start,
                end=self._current_start + self.interval,
                packets=self._current_packets,
                bytes=self._current_bytes,
            )
        )
        self._current_start = None
        self._current_packets = 0
        self._current_bytes = 0

    def _track_endpoints(self, packet, packet_len: int) -> None:
        src = None
        dst = None

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst

        for ip in (src, dst):
            if not ip:
                continue
            self.endpoint_stats[ip][0] += 1
            self.endpoint_stats[ip][1] += packet_len

    def _spike_threshold(self, baseline_values: List[float]) -> tuple[float, float, float]:
        mean = statistics.fmean(baseline_values)
        std = statistics.pstdev(baseline_values) if len(baseline_values) > 1 else 0.0
        median = statistics.median(baseline_values)
        mad = statistics.median([abs(v - median) for v in baseline_values]) if baseline_values else 0.0

        z_threshold = mean + self.spike_zscore * (std if std > 0 else 1.0)
        factor_threshold = mean * self.min_spike_factor
        robust_threshold = median + 6 * mad
        threshold = max(z_threshold, factor_threshold, robust_threshold)
        return mean, std, threshold

    def detect_spikes(self) -> List[Spike]:
        spikes: List[Spike] = []
        if len(self.windows) < self.min_baseline_windows + 1:
            return spikes

        metric_extractors = {
            "bytes": lambda w: w.bytes,
            "packets": lambda w: w.packets,
        }

        for metric, extractor in metric_extractors.items():
            for idx in range(self.min_baseline_windows, len(self.windows)):
                baseline = self.windows[max(0, idx - self.lookback) : idx]
                if len(baseline) < self.min_baseline_windows:
                    continue

                current_window = self.windows[idx]
                current_value = extractor(current_window)
                if metric == "bytes" and current_value < self.min_alert_bytes:
                    continue
                if metric == "packets" and current_value < self.min_alert_packets:
                    continue

                baseline_values = [extractor(w) for w in baseline]
                mean, std, threshold = self._spike_threshold(baseline_values)
                if current_value <= threshold:
                    continue

                ratio = current_value / mean if mean > 0 else float("inf")
                zscore = (current_value - mean) / std if std > 0 else float("inf")
                spikes.append(
                    Spike(
                        metric=metric,
                        window=current_window,
                        baseline_mean=mean,
                        baseline_std=std,
                        threshold=threshold,
                        ratio=ratio,
                        zscore=zscore,
                    )
                )

        # Deduplicate by (window.start, metric) to avoid repeated near-identical entries.
        deduped: Dict[tuple, Spike] = {}
        for spike in spikes:
            key = (spike.window.start, spike.metric)
            if key not in deduped or spike.ratio > deduped[key].ratio:
                deduped[key] = spike
        return sorted(deduped.values(), key=lambda s: (s.window.start, s.metric))

    def top_endpoints(self, count: int = 5) -> List[tuple]:
        return sorted(
            self.endpoint_stats.items(),
            key=lambda item: item[1][1],
            reverse=True,
        )[:count]

    def render_report(self, pcap_path: Path, top_n: int = 5) -> str:
        if self.total_packets == 0:
            return (
                "=== Network Traffic Analyzer Report ===\n"
                f"PCAP: {pcap_path}\n"
                "No packets captured/analyzed."
            )

        duration = max((self.last_ts or 0) - (self.first_ts or 0), 0.0)
        spikes = self.detect_spikes()

        start = datetime.fromtimestamp(self.first_ts).isoformat(sep=" ", timespec="seconds")
        end = datetime.fromtimestamp(self.last_ts).isoformat(sep=" ", timespec="seconds")
        avg_pps = self.total_packets / duration if duration > 0 else float(self.total_packets)
        avg_bps = self.total_bytes / duration if duration > 0 else float(self.total_bytes)

        lines = [
            "=== Network Traffic Analyzer Report ===",
            f"PCAP: {pcap_path}",
            f"Capture start: {start}",
            f"Capture end:   {end}",
            f"Duration:      {duration:.2f}s",
            f"Total packets: {self.total_packets}",
            f"Total bytes:   {self.total_bytes} ({format_bytes(self.total_bytes)})",
            f"Average rate:  {avg_pps:.2f} packets/s, {format_bytes(avg_bps)}/s",
            f"Time window:   {self.interval:.2f}s",
            "",
            f"Detected spikes: {len(spikes)}",
        ]

        if spikes:
            for spike in spikes:
                window_start = datetime.fromtimestamp(spike.window.start).strftime("%H:%M:%S")
                window_end = datetime.fromtimestamp(spike.window.end).strftime("%H:%M:%S")
                lines.append(
                    "  "
                    f"- {spike.metric.upper()} spike [{window_start} - {window_end}] "
                    f"value={getattr(spike.window, spike.metric)} "
                    f"threshold={spike.threshold:.2f} "
                    f"ratio={spike.ratio:.2f}x "
                    f"z={spike.zscore:.2f}"
                )
        else:
            lines.append("  - No unusual spikes found with current thresholds.")

        top = self.top_endpoints(top_n)
        lines.extend(["", f"Top endpoints by observed bytes (top {top_n}):"])
        if not top:
            lines.append("  - No IP endpoints found.")
        else:
            for ip, (packets, byte_count) in top:
                lines.append(f"  - {ip}: packets={packets}, bytes={byte_count} ({format_bytes(byte_count)})")

        return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture network traffic with Scapy and detect unusual volume spikes."
    )

    capture_group = parser.add_argument_group("capture options")
    capture_group.add_argument(
        "--offline",
        metavar="PCAP",
        help="Analyze an existing .pcap file instead of capturing live traffic.",
    )
    capture_group.add_argument(
        "--output",
        metavar="PCAP",
        help="Output .pcap path for live capture. Default: captures/traffic_<timestamp>.pcap",
    )
    capture_group.add_argument("--iface", help="Interface to capture from (default: Scapy default).")
    capture_group.add_argument("--filter", dest="bpf_filter", help="BPF filter (e.g. 'tcp or udp').")
    capture_group.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Capture duration in seconds for live capture (default: 60).",
    )
    capture_group.add_argument(
        "--count",
        type=int,
        default=0,
        help="Stop after capturing this many packets (default: 0 = unlimited until timeout/Ctrl+C).",
    )

    analysis_group = parser.add_argument_group("analysis options")
    analysis_group.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Time bucket size in seconds (default: 1.0).",
    )
    analysis_group.add_argument(
        "--lookback",
        type=int,
        default=20,
        help="Number of previous windows used as baseline (default: 20).",
    )
    analysis_group.add_argument(
        "--min-baseline",
        type=int,
        default=5,
        help="Minimum baseline windows required before spike detection (default: 5).",
    )
    analysis_group.add_argument(
        "--zscore",
        type=float,
        default=3.0,
        help="Z-score component for spike threshold (default: 3.0).",
    )
    analysis_group.add_argument(
        "--factor",
        type=float,
        default=2.0,
        help="Multiplicative factor vs baseline mean for spike threshold (default: 2.0).",
    )
    analysis_group.add_argument(
        "--min-alert-packets",
        type=int,
        default=20,
        help="Minimum packets in a window before packet spike alerting (default: 20).",
    )
    analysis_group.add_argument(
        "--min-alert-bytes",
        type=int,
        default=20_000,
        help="Minimum bytes in a window before byte spike alerting (default: 20000).",
    )
    analysis_group.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top endpoints to show in report (default: 5).",
    )
    analysis_group.add_argument(
        "--report",
        metavar="TXT",
        help="Optional path to save a text analysis report.",
    )

    return parser.parse_args()


def default_pcap_path() -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("captures") / f"traffic_{stamp}.pcap"


def create_analyzer(args: argparse.Namespace) -> TrafficAnalyzer:
    return TrafficAnalyzer(
        interval=args.interval,
        lookback=args.lookback,
        min_baseline_windows=args.min_baseline,
        spike_zscore=args.zscore,
        min_spike_factor=args.factor,
        min_alert_packets=args.min_alert_packets,
        min_alert_bytes=args.min_alert_bytes,
    )


def capture_live(args: argparse.Namespace, analyzer: TrafficAnalyzer) -> Path:
    pcap_path = Path(args.output) if args.output else default_pcap_path()
    pcap_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[+] Starting capture -> {pcap_path}")
    if args.iface:
        print(f"[+] Interface: {args.iface}")
    if args.bpf_filter:
        print(f"[+] BPF filter: {args.bpf_filter}")
    if args.duration > 0:
        print(f"[+] Duration: {args.duration}s")
    if args.count > 0:
        print(f"[+] Packet limit: {args.count}")
    print("[+] Press Ctrl+C to stop early.\n")

    writer = PcapWriter(str(pcap_path), append=False, sync=True)
    try:
        def on_packet(packet) -> None:
            packet_len = len(packet)
            analyzer.observe(packet.time, packet_len, packet)
            writer.write(packet)

        sniff(
            iface=args.iface if args.iface else None,
            filter=args.bpf_filter if args.bpf_filter else None,
            prn=on_packet,
            store=False,
            timeout=args.duration if args.duration > 0 else None,
            count=args.count if args.count > 0 else 0,
        )
    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user.")
    finally:
        writer.close()

    analyzer.finalize()
    return pcap_path


def analyze_pcap_file(pcap_path: Path, analyzer: TrafficAnalyzer) -> Path:
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    print(f"[+] Reading PCAP: {pcap_path}")
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            analyzer.observe(packet.time, len(packet), packet)
    analyzer.finalize()
    return pcap_path


def write_report(report_text: str, report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")
    print(f"[+] Saved report -> {report_path}")


def main() -> None:
    args = parse_args()
    if SCAPY_IMPORT_ERROR is not None:
        print("[!] Scapy is required but not installed in this environment.")
        print("    Install it with: pip install scapy")
        raise SystemExit(1)

    analyzer = create_analyzer(args)

    try:
        if args.offline:
            pcap_path = analyze_pcap_file(Path(args.offline), analyzer)
        else:
            pcap_path = capture_live(args, analyzer)
    except PermissionError:
        print(
            "[!] Permission error while capturing traffic. "
            "Try running with elevated privileges (e.g. sudo)."
        )
        raise SystemExit(1)
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        raise SystemExit(1)
    except OSError as exc:
        print(f"[!] OS error: {exc}")
        raise SystemExit(1)

    print()
    report = analyzer.render_report(pcap_path=pcap_path, top_n=max(args.top, 1))
    print(report)

    if args.report:
        write_report(report, Path(args.report))


if __name__ == "__main__":
    main()
