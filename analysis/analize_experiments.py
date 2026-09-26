from pathlib import Path

script = r'''#!/usr/bin/env python3
"""
Analyze experiment folders produced by experiment.sh.

Expected structure per experiment directory:
- params.json
- cpu.txt
- network.txt
- capture.pcap (optional; requires tshark)
- tcpdump.pid (ignored)

The script:
- scans all subfolders
- parses CPU and network logs
- optionally extracts pcap metrics via tshark
- writes summary CSV
- generates per-experiment and comparison plots
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import matplotlib.pyplot as plt
import pandas as pd


CPU_HEADER_RE = re.compile(r"^\s*\d{2}:\d{2}:\d{2}\s+UID\s+PID\s+%usr")
NETWORK_HEADER_RE = re.compile(r"^\s*\d{2}:\d{2}:\d{2}\s+IFACE\s+rxpck/s")


def normalize_number(value: str) -> float:
    value = value.strip().replace(",", ".")
    if value in {"", "-", "NA", "N/A"}:
        return float("nan")
    return float(value)


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return result.stdout


def find_experiment_dirs(root: Path) -> list[Path]:
    dirs = []
    for p in sorted(root.iterdir()):
        if p.is_dir() and (p / "params.json").exists():
            dirs.append(p)
    return dirs


def load_params(exp_dir: Path) -> dict[str, Any]:
    with open(exp_dir / "params.json", "r", encoding="utf-8") as f:
        return json.load(f)


def parse_cpu_txt(path: Path) -> pd.DataFrame:
    """
    Parse pidstat output.

    Output columns:
    - time: string HH:MM:SS
    - uid, pid, usr, system, guest, wait, cpu, cpu_core, command
    """
    rows: list[dict[str, Any]] = []
    current_time: str | None = None

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue

            if CPU_HEADER_RE.match(line):
                # header line contains the timestamp at the beginning
                current_time = line.split()[0]
                continue

            if current_time is None:
                continue

            # Data lines begin with the sample timestamp.
            parts = line.split()
            if len(parts) < 9:
                continue
            if not re.match(r"^\d{2}:\d{2}:\d{2}$", parts[0]):
                continue

            # Format:
            # time UID PID %usr %system %guest %wait %CPU CPU Command...
            try:
                time_str = parts[0]
                uid = int(parts[1])
                pid = int(parts[2])
                usr = normalize_number(parts[3])
                system = normalize_number(parts[4])
                guest = normalize_number(parts[5])
                wait = normalize_number(parts[6])
                cpu = normalize_number(parts[7])
                cpu_core = parts[8]
                command = " ".join(parts[9:]) if len(parts) > 9 else ""
            except Exception:
                continue

            rows.append(
                {
                    "time": time_str,
                    "uid": uid,
                    "pid": pid,
                    "usr": usr,
                    "system": system,
                    "guest": guest,
                    "wait": wait,
                    "cpu": cpu,
                    "cpu_core": cpu_core,
                    "command": command,
                }
            )

    if not rows:
        return pd.DataFrame(columns=["time", "uid", "pid", "usr", "system", "guest", "wait", "cpu", "cpu_core", "command"])

    df = pd.DataFrame(rows)
    df["time"] = pd.to_datetime(df["time"], format="%H:%M:%S", errors="coerce")
    df = df.dropna(subset=["time"])
    return df


def parse_network_txt(path: Path, iface: str | None = None) -> pd.DataFrame:
    """
    Parse sar -n DEV output.

    Output columns:
    - time
    - iface
    - rxpck_s, txpck_s, rxkB_s, txkB_s, rxcmp_s, txcmp_s, rxmcst_s, ifutil
    """
    rows: list[dict[str, Any]] = []
    current_time: str | None = None
    current_header_seen = False

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue

            if NETWORK_HEADER_RE.match(line):
                current_time = line.split()[0]
                current_header_seen = True
                continue

            if not current_header_seen or current_time is None:
                continue

            parts = line.split()
            if len(parts) < 9:
                continue
            if not re.match(r"^\d{2}:\d{2}:\d{2}$", parts[0]):
                continue

            try:
                time_str = parts[0]
                iface_name = parts[1]
                rxpck_s = normalize_number(parts[2])
                txpck_s = normalize_number(parts[3])
                rxkB_s = normalize_number(parts[4])
                txkB_s = normalize_number(parts[5])
                rxcmp_s = normalize_number(parts[6])
                txcmp_s = normalize_number(parts[7])
                rxmcst_s = normalize_number(parts[8])
                ifutil = normalize_number(parts[9]) if len(parts) > 9 else float("nan")
            except Exception:
                continue

            if iface is not None and iface_name != iface:
                continue

            rows.append(
                {
                    "time": time_str,
                    "iface": iface_name,
                    "rxpck_s": rxpck_s,
                    "txpck_s": txpck_s,
                    "rxkB_s": rxkB_s,
                    "txkB_s": txkB_s,
                    "rxcmp_s": rxcmp_s,
                    "txcmp_s": txcmp_s,
                    "rxmcst_s": rxmcst_s,
                    "ifutil": ifutil,
                }
            )

    if not rows:
        return pd.DataFrame(columns=["time", "iface", "rxpck_s", "txpck_s", "rxkB_s", "txkB_s", "rxcmp_s", "txcmp_s", "rxmcst_s", "ifutil"])

    df = pd.DataFrame(rows)
    df["time"] = pd.to_datetime(df["time"], format="%H:%M:%S", errors="coerce")
    df = df.dropna(subset=["time"])
    return df


def tshark_available() -> bool:
    try:
        subprocess.run(["tshark", "-v"], capture_output=True, text=True, check=True)
        return True
    except Exception:
        return False


def analyze_pcap(pcap_path: Path) -> dict[str, Any]:
    """
    Optional pcap metrics using tshark.
    """
    if not pcap_path.exists() or not tshark_available():
        return {}

    metrics: dict[str, Any] = {}

    # Basic packet and byte counts
    try:
        out = run_cmd([
            "tshark",
            "-r", str(pcap_path),
            "-q",
            "-z", "io,stat,1",
        ])
        metrics["tshark_io_stat"] = out
    except Exception:
        pass

    # Total packets
    try:
        out = run_cmd(["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "frame.len"])
        lengths = [int(x) for x in out.splitlines() if x.strip().isdigit()]
        metrics["packet_count"] = len(lengths)
        metrics["total_bytes"] = sum(lengths)
    except Exception:
        pass

    # TCP retransmissions and dup ACKs
    try:
        out = run_cmd(["tshark", "-r", str(pcap_path), "-Y", "tcp.analysis.retransmission", "-T", "fields", "-e", "frame.number"])
        metrics["tcp_retransmissions"] = len([x for x in out.splitlines() if x.strip()])
    except Exception:
        metrics["tcp_retransmissions"] = 0

    try:
        out = run_cmd(["tshark", "-r", str(pcap_path), "-Y", "tcp.analysis.duplicate_ack", "-T", "fields", "-e", "frame.number"])
        metrics["tcp_duplicate_acks"] = len([x for x in out.splitlines() if x.strip()])
    except Exception:
        metrics["tcp_duplicate_acks"] = 0

    try:
        out = run_cmd(["tshark", "-r", str(pcap_path), "-Y", "tcp.analysis.out_of_order", "-T", "fields", "-e", "frame.number"])
        metrics["tcp_out_of_order"] = len([x for x in out.splitlines() if x.strip()])
    except Exception:
        metrics["tcp_out_of_order"] = 0

    return metrics


def summarize_cpu(df: pd.DataFrame) -> dict[str, Any]:
    if df.empty:
        return {
            "cpu_mean_sum": float("nan"),
            "cpu_max_sum": float("nan"),
            "cpu_p95_sum": float("nan"),
            "top_command": "",
            "top_command_mean_cpu": float("nan"),
        }

    # Remove pidstat itself from "overall load" if desired? We keep it in raw,
    # but it is usually small and does not distort much.
    per_time = df.groupby("time", as_index=False)["cpu"].sum().rename(columns={"cpu": "cpu_sum"})
    summary = {
        "cpu_mean_sum": float(per_time["cpu_sum"].mean()),
        "cpu_max_sum": float(per_time["cpu_sum"].max()),
        "cpu_p95_sum": float(per_time["cpu_sum"].quantile(0.95)),
    }

    by_cmd = (
        df[df["command"].str.lower() != "pidstat"]
        .groupby("command", as_index=False)["cpu"]
        .mean()
        .sort_values("cpu", ascending=False)
    )
    if not by_cmd.empty:
        summary["top_command"] = str(by_cmd.iloc[0]["command"])
        summary["top_command_mean_cpu"] = float(by_cmd.iloc[0]["cpu"])
    else:
        summary["top_command"] = ""
        summary["top_command_mean_cpu"] = float("nan")

    return summary


def summarize_network(df: pd.DataFrame) -> dict[str, Any]:
    if df.empty:
        return {
            "rxkB_s_mean": float("nan"),
            "txkB_s_mean": float("nan"),
            "rxkB_s_max": float("nan"),
            "txkB_s_max": float("nan"),
            "throughput_kB_s_mean": float("nan"),
            "throughput_kB_s_max": float("nan"),
        }

    throughput = df["rxkB_s"] + df["txkB_s"]
    return {
        "rxkB_s_mean": float(df["rxkB_s"].mean()),
        "txkB_s_mean": float(df["txkB_s"].mean()),
        "rxkB_s_max": float(df["rxkB_s"].max()),
        "txkB_s_max": float(df["txkB_s"].max()),
        "throughput_kB_s_mean": float(throughput.mean()),
        "throughput_kB_s_max": float(throughput.max()),
    }


def make_timeseries_plot(df: pd.DataFrame, x: str, ys: list[str], title: str, ylabel: str, out_path: Path) -> None:
    if df.empty:
        return

    plt.figure(figsize=(12, 6))
    for y in ys:
        if y in df.columns:
            plt.plot(df[x], df[y], label=y)
    plt.title(title)
    plt.xlabel("time")
    plt.ylabel(ylabel)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def make_bar_plot(summary_df: pd.DataFrame, x: str, y: str, title: str, ylabel: str, out_path: Path, rotation: int = 30) -> None:
    if summary_df.empty:
        return

    plt.figure(figsize=(12, 6))
    plt.bar(summary_df[x].astype(str), summary_df[y])
    plt.title(title)
    plt.xlabel(x)
    plt.ylabel(ylabel)
    plt.xticks(rotation=rotation, ha="right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def experiment_label(params: dict[str, Any]) -> str:
    return f"{params.get('transport', 'unknown')} / {params.get('scenario', 'unknown')}"


def analyze_experiment(exp_dir: Path, out_dir: Path) -> dict[str, Any]:
    params = load_params(exp_dir)
    label = experiment_label(params)
    exp_out = out_dir / exp_dir.name
    safe_mkdir(exp_out)

    cpu_path = exp_dir / "cpu.txt"
    net_path = exp_dir / "network.txt"
    pcap_path = exp_dir / "capture.pcap"

    cpu_df = parse_cpu_txt(cpu_path) if cpu_path.exists() else pd.DataFrame()
    net_df = parse_network_txt(net_path, iface=params.get("interface")) if net_path.exists() else pd.DataFrame()
    pcap_metrics = analyze_pcap(pcap_path)

    cpu_summary = summarize_cpu(cpu_df)
    net_summary = summarize_network(net_df)

    # Save parsed tables for further analysis
    if not cpu_df.empty:
        cpu_df.to_csv(exp_out / "cpu_parsed.csv", index=False)
    if not net_df.empty:
        net_df.to_csv(exp_out / "network_parsed.csv", index=False)

    # Per-experiment plots
    if not cpu_df.empty:
        cpu_per_time = cpu_df.groupby("time", as_index=False)["cpu"].sum().rename(columns={"cpu": "cpu_sum"})
        make_timeseries_plot(
            cpu_per_time,
            x="time",
            ys=["cpu_sum"],
            title=f"CPU load over time — {label}",
            ylabel="%CPU summed across processes",
            out_path=exp_out / "cpu_over_time.png",
        )

        top_cmds = (
            cpu_df[cpu_df["command"].str.lower() != "pidstat"]
            .groupby("command", as_index=False)["cpu"]
            .mean()
            .sort_values("cpu", ascending=False)
            .head(10)
        )
        if not top_cmds.empty:
            make_bar_plot(
                top_cmds,
                x="command",
                y="cpu",
                title=f"Top processes by mean CPU — {label}",
                ylabel="mean %CPU",
                out_path=exp_out / "top_processes.png",
                rotation=35,
            )

    if not net_df.empty:
        net_plot_df = net_df.copy()
        net_plot_df["throughput_kB_s"] = net_plot_df["rxkB_s"] + net_plot_df["txkB_s"]
        make_timeseries_plot(
            net_plot_df,
            x="time",
            ys=["rxkB_s", "txkB_s", "throughput_kB_s"],
            title=f"Network throughput over time — {label}",
            ylabel="kB/s",
            out_path=exp_out / "network_over_time.png",
        )

    # Write per-experiment summary
    summary = {
        "experiment_dir": exp_dir.name,
        "scenario": params.get("scenario"),
        "transport": params.get("transport"),
        "duration": params.get("duration"),
        "interface": params.get("interface"),
        "timestamp": params.get("timestamp"),
        **cpu_summary,
        **net_summary,
        **pcap_metrics,
    }

    with open(exp_out / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    return summary


def build_comparison_plots(summary_df: pd.DataFrame, out_dir: Path) -> None:
    if summary_df.empty:
        return

    # Sort for consistent plots
    ordered = summary_df.sort_values(["transport", "scenario", "experiment_dir"]).copy()

    # CPU summary
    make_bar_plot(
        ordered,
        x="experiment_dir",
        y="cpu_mean_sum",
        title="Average summed CPU load by experiment",
        ylabel="mean summed %CPU",
        out_path=out_dir / "compare_cpu_mean.png",
        rotation=45,
    )

    # Network throughput summary
    make_bar_plot(
        ordered,
        x="experiment_dir",
        y="throughput_kB_s_mean",
        title="Average network throughput by experiment",
        ylabel="mean rx+tx kB/s",
        out_path=out_dir / "compare_throughput_mean.png",
        rotation=45,
    )

    # TCP retransmissions if present
    if "tcp_retransmissions" in ordered.columns and ordered["tcp_retransmissions"].notna().any():
        tmp = ordered.fillna({"tcp_retransmissions": 0})
        make_bar_plot(
            tmp,
            x="experiment_dir",
            y="tcp_retransmissions",
            title="TCP retransmissions by experiment",
            ylabel="count",
            out_path=out_dir / "compare_tcp_retransmissions.png",
            rotation=45,
        )

    # Grouped table by scenario/transport
    pivot_cols = [c for c in ["cpu_mean_sum", "throughput_kB_s_mean", "tcp_retransmissions", "tcp_duplicate_acks", "tcp_out_of_order"] if c in ordered.columns]
    if pivot_cols:
        pivot = ordered[["transport", "scenario", "experiment_dir"] + pivot_cols].copy()
        pivot.to_csv(out_dir / "comparison_summary.csv", index=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze experiment folders and generate plots.")
    parser.add_argument("root", nargs="?", default="results", help="Root directory containing experiment folders")
    parser.add_argument("--out", default="analysis_out", help="Output directory for plots and summaries")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()
    safe_mkdir(out_dir)

    exp_dirs = find_experiment_dirs(root)
    if not exp_dirs:
        raise SystemExit(f"No experiment directories with params.json found in: {root}")

    summaries = []
    for exp_dir in exp_dirs:
        try:
            print(f"Analyzing {exp_dir.name} ...")
            summary = analyze_experiment(exp_dir, out_dir)
            summaries.append(summary)
        except Exception as e:
            print(f"  Failed: {e}")

    summary_df = pd.DataFrame(summaries)
    if summary_df.empty:
        raise SystemExit("No experiments could be analyzed.")

    summary_df.to_csv(out_dir / "all_experiments_summary.csv", index=False)
    build_comparison_plots(summary_df, out_dir)

    print("\nDone.")
    print(f"Summary: {out_dir / 'all_experiments_summary.csv'}")
    print(f"Plots:   {out_dir}")


if __name__ == "__main__":
    main()
'''

path = Path('/mnt/data/analyze_experiments.py')
path.write_text(script, encoding='utf-8')
print(path)
