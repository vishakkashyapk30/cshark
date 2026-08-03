#!/usr/bin/env python3
"""
anomaly_detect.py - AI/ML-assisted anomaly triage for C-Shark flow exports.

This is a *second, complementary* detection layer on top of C-Shark's C-side
rule-based detectors (detect.c: port-scan / ARP-spoof). Those catch known
signatures deterministically; this script does unsupervised outlier scoring
over per-source-IP flow statistics, so it can surface unusual traffic that
doesn't match a fixed rule - the same idea behind "bring in AI/ML expertise
to minimize or eliminate human dependencies across deployment workflows".

Input: the CSV produced by C-Shark's `export_session_csv()`
(packet_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,length,tcp_flags,info)

Optional: the CSV produced by `export_alerts_csv()`, used only to cross-reference
which source IPs were *also* flagged by the deterministic C detectors.

Usage:
    python3 anomaly_detect.py session_flows.csv
    python3 anomaly_detect.py session_flows.csv --alerts session_alerts.csv --top 5
    python3 anomaly_detect.py session_flows.csv --json anomalies.json

Dependency policy (mirrors the C side's "zero external deps unless it earns
its keep" philosophy):
    - Uses only the standard library by default (median/MAD-based robust
      z-score outlier scoring).
    - If scikit-learn is installed (see requirements.txt), automatically
      upgrades to an IsolationForest model for the same job. Either path
      produces the same output shape, so downstream consumers (the
      PowerShell workflow, a human reading the report) don't care which
      one ran.
"""

import argparse
import csv
import json
import re
import statistics
import sys
from collections import defaultdict

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    _HAVE_SKLEARN = True
except ImportError:
    _HAVE_SKLEARN = False

FEATURE_NAMES = [
    "packet_count",
    "distinct_dst_ports",
    "distinct_dst_ips",
    "total_bytes",
    "mean_packet_size",
    "syn_only_ratio",
]

IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def load_flow_rows(csv_path):
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except FileNotFoundError:
        print(f"error: flow CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"error: could not read {csv_path}: {e}", file=sys.stderr)
        sys.exit(1)

    required = {"src_ip", "dst_ip", "dst_port", "length", "tcp_flags"}
    if rows and not required.issubset(reader.fieldnames or []):
        print(
            f"error: {csv_path} doesn't look like a C-Shark flow export "
            f"(missing columns: {required - set(reader.fieldnames or [])})",
            file=sys.stderr,
        )
        sys.exit(1)
    return rows


def build_features(rows):
    """Aggregate per-source-IP flow statistics into feature vectors."""
    per_ip_ports = defaultdict(set)
    per_ip_dst_ips = defaultdict(set)
    per_ip_bytes = defaultdict(int)
    per_ip_count = defaultdict(int)
    per_ip_syn_only = defaultdict(int)

    for row in rows:
        src = row.get("src_ip", "").strip()
        if not src:
            continue
        per_ip_count[src] += 1
        try:
            per_ip_bytes[src] += int(row.get("length", 0) or 0)
        except ValueError:
            pass
        dst_port = row.get("dst_port", "")
        if dst_port:
            per_ip_ports[src].add(dst_port)
        dst_ip = row.get("dst_ip", "")
        if dst_ip:
            per_ip_dst_ips[src].add(dst_ip)
        flags = row.get("tcp_flags", "") or ""
        if "SYN" in flags and "ACK" not in flags:
            per_ip_syn_only[src] += 1

    features = {}
    for ip, count in per_ip_count.items():
        total_bytes = per_ip_bytes[ip]
        features[ip] = {
            "packet_count": count,
            "distinct_dst_ports": len(per_ip_ports[ip]),
            "distinct_dst_ips": len(per_ip_dst_ips[ip]),
            "total_bytes": total_bytes,
            "mean_packet_size": total_bytes / count if count else 0.0,
            "syn_only_ratio": per_ip_syn_only[ip] / count if count else 0.0,
        }
    return features


def score_with_isolation_forest(features):
    ips = list(features.keys())
    matrix = np.array([[features[ip][f] for f in FEATURE_NAMES] for ip in ips])
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(matrix)
    # decision_function: higher = more normal, so invert for an "anomaly score"
    raw_scores = -model.decision_function(matrix)
    scores = {ip: float(s) for ip, s in zip(ips, raw_scores)}
    return scores, "IsolationForest (scikit-learn)"


def score_with_robust_zscore(features):
    """Dependency-free fallback: modified z-score (median + MAD) per feature,
    combined via the max absolute z-score across features. This is the same
    outlier-detection idea used in basic network/security monitoring before
    reaching for a full ML model - robust to the small sample sizes typical
    of a short capture session."""
    ips = list(features.keys())
    scores = {ip: 0.0 for ip in ips}

    for feature in FEATURE_NAMES:
        values = [features[ip][feature] for ip in ips]
        if len(values) < 2:
            continue
        median = statistics.median(values)
        abs_devs = [abs(v - median) for v in values]
        mad = statistics.median(abs_devs)
        if mad == 0:
            # Fall back to mean absolute deviation if MAD collapses to 0
            # (common with small samples / many identical values)
            mean_dev = sum(abs_devs) / len(abs_devs)
            if mean_dev == 0:
                continue
            for ip, v in zip(ips, values):
                z = abs(v - median) / mean_dev
                scores[ip] = max(scores[ip], z)
            continue
        for ip, v in zip(ips, values):
            # 0.6745 makes MAD comparable to a standard deviation for normal data
            z = 0.6745 * abs(v - median) / mad
            scores[ip] = max(scores[ip], z)

    return scores, "Robust modified z-score (median/MAD, stdlib-only fallback)"


def load_rule_flagged_ips(alerts_csv_path):
    """Extract source IPs already flagged by detect.c's rule-based alerts,
    so the ML output can show where the two detection layers agree."""
    if not alerts_csv_path:
        return {}

    flagged = defaultdict(set)
    try:
        with open(alerts_csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                alert_type = row.get("type", "unknown")
                details = row.get("details", "")
                for ip in IPV4_RE.findall(details):
                    flagged[ip].add(alert_type)
    except FileNotFoundError:
        print(f"warning: alerts CSV not found: {alerts_csv_path} (skipping cross-reference)",
              file=sys.stderr)
    return flagged


def main():
    parser = argparse.ArgumentParser(
        description="AI/ML-assisted anomaly triage over a C-Shark flow CSV export.")
    parser.add_argument("csv", help="Path to the CSV from export_session_csv()")
    parser.add_argument("--alerts", help="Path to the CSV from export_alerts_csv() "
                         "(optional, used only to cross-reference rule-based alerts)")
    parser.add_argument("--top", type=int, default=10, help="Number of top anomalies to display (default: 10)")
    parser.add_argument("--json", help="Also write the full ranked result to this JSON path")
    args = parser.parse_args()

    rows = load_flow_rows(args.csv)
    if not rows:
        print("No flow records found - nothing to analyze.")
        sys.exit(0)

    features = build_features(rows)
    if len(features) < 2:
        print(f"Only {len(features)} distinct source IP(s) in this capture - "
              "not enough data for meaningful outlier scoring (need >= 2).")
        sys.exit(0)

    if _HAVE_SKLEARN:
        scores, method = score_with_isolation_forest(features)
    else:
        scores, method = score_with_robust_zscore(features)

    rule_flagged = load_rule_flagged_ips(args.alerts)

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)

    print(f"C-Shark AI/ML Anomaly Triage  ({method})")
    print(f"Analyzed {len(rows)} flow records across {len(features)} source IPs from '{args.csv}'")
    if args.alerts:
        print(f"Cross-referenced with rule-based alerts from '{args.alerts}'")
    print("=" * 100)
    header = f"{'Rank':<5}{'Source IP':<18}{'Score':<10}{'Pkts':<7}{'DstPorts':<10}{'DstIPs':<8}{'Bytes':<10}{'SYN-only':<10}{'Rule Flags'}"
    print(header)
    print("-" * 100)

    for rank, (ip, score) in enumerate(ranked[: args.top], start=1):
        f = features[ip]
        flags = ",".join(sorted(rule_flagged.get(ip, []))) or "-"
        print(f"{rank:<5}{ip:<18}{score:<10.3f}{f['packet_count']:<7}"
              f"{f['distinct_dst_ports']:<10}{f['distinct_dst_ips']:<8}"
              f"{f['total_bytes']:<10}{f['syn_only_ratio']:<10.2f}{flags}")

    print("=" * 100)
    agreement = sum(1 for ip, _ in ranked[: args.top] if ip in rule_flagged)
    print(f"{agreement}/{min(args.top, len(ranked))} of the top ML-flagged IPs were also "
          "flagged by C-Shark's rule-based detectors.")

    if args.json:
        payload = {
            "method": method,
            "source_csv": args.csv,
            "results": [
                {
                    "src_ip": ip,
                    "anomaly_score": score,
                    "features": features[ip],
                    "rule_based_alerts": sorted(rule_flagged.get(ip, [])),
                }
                for ip, score in ranked
            ],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\nFull ranked results written to '{args.json}'")


if __name__ == "__main__":
    main()
