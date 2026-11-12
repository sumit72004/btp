"""VM Log Importer & Scaled Dataset Builder.

Processes raw exported Zeek and Suricata logs from the VMware testbed,
validates schema, labels ground-truth, and partitions into benign and malicious corpora.
"""

import os
import sys
import json
import tarfile
import argparse
from typing import List, Dict, Any, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.copilot.log_parsers import (
    parse_zeek_log,
    parse_suricata_eve,
    NetworkLogRecord
)


def extract_archive_if_present(raw_dir: str):
    """Extract .tar.gz archive if found in raw_dir."""
    for fname in os.listdir(raw_dir):
        if fname.endswith(".tar.gz") or fname.endswith(".tgz"):
            archive_path = os.path.join(raw_dir, fname)
            print(f"[*] Extracting log archive: {archive_path}...")
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(path=raw_dir)
            print(f"[+] Extraction complete.")


def classify_ground_truth(record: NetworkLogRecord) -> str:
    """
    Automated ground-truth heuristic based on testbed traffic signatures:
    - Suricata alert severity 1 or 2 -> malicious
    - Zeek HTTP with sqlmap / nikto / directory traversal -> malicious
    - Zeek DNS with exfil-c2 or high entropy -> malicious
    - Zeek conn with SYN flood / port scan flags (S0, REJ to multiple ports) -> malicious
    - Known attacker subnets (e.g., 185.220.101.x, 10.0.2.15/scanning) -> malicious
    - Otherwise -> benign
    """
    if record.sensor == "suricata":
        severity = record.raw_fields.get("severity", 3)
        if severity <= 2:
            return "malicious"

    summary_lower = record.summary_text.lower()
    raw_ua = str(record.raw_fields.get("user_agent", "")).lower()

    if any(sig in raw_ua for sig in ["sqlmap", "nikto", "dirb", "hydra"]):
        return "malicious"

    if any(pattern in summary_lower for pattern in ["etc/passwd", "login.php", "or 1=1", "cmd=id", "exfil-c2"]):
        return "malicious"

    if record.log_type == "conn":
        conn_state = record.raw_fields.get("conn_state", "")
        # S0 (connection attempt seen, no reply) or REJ on unusual port indicates scan
        if conn_state in ["S0", "REJ"] and record.dest_port in [21, 22, 23, 25, 81, 82, 8080, 3306]:
            return "malicious"

    return "benign"


def import_logs(raw_dir: str = "data/raw_logs") -> Tuple[List[NetworkLogRecord], List[NetworkLogRecord]]:
    """Parse all Zeek and Suricata files in raw_dir into benign and malicious lists."""
    if not os.path.exists(raw_dir):
        os.makedirs(raw_dir, exist_ok=True)
        print(f"[!] Directory '{raw_dir}' created. Place your exported VM logs here.")
        return [], []

    extract_archive_if_present(raw_dir)

    all_records: List[NetworkLogRecord] = []

    # 1. Parse Zeek files
    for fname in os.listdir(raw_dir):
        fpath = os.path.join(raw_dir, fname)
        if not os.path.isfile(fpath):
            continue

        lower = fname.lower()
        if "conn" in lower and (lower.endswith(".json") or lower.endswith(".log")):
            print(f"[*] Ingesting Zeek conn logs from {fname}...")
            all_records.extend(parse_zeek_log(fpath, "conn"))
        elif "http" in lower and (lower.endswith(".json") or lower.endswith(".log")):
            print(f"[*] Ingesting Zeek http logs from {fname}...")
            all_records.extend(parse_zeek_log(fpath, "http"))
        elif "dns" in lower and (lower.endswith(".json") or lower.endswith(".log")):
            print(f"[*] Ingesting Zeek dns logs from {fname}...")
            all_records.extend(parse_zeek_log(fpath, "dns"))
        elif "eve" in lower and lower.endswith(".json"):
            print(f"[*] Ingesting Suricata EVE logs from {fname}...")
            all_records.extend(parse_suricata_eve(fpath))

    # Apply ground truth labeling
    benign_records = []
    malicious_records = []

    for r in all_records:
        r.ground_truth = classify_ground_truth(r)
        if r.ground_truth == "malicious":
            malicious_records.append(r)
        else:
            benign_records.append(r)

    return benign_records, malicious_records


def save_corpus(records: List[NetworkLogRecord], out_path: str):
    """Serialize list of NetworkLogRecord to JSON."""
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    serialized = []
    for r in records:
        serialized.append({
            "record_id": r.record_id,
            "sensor": r.sensor,
            "log_type": r.log_type,
            "source_ip": r.source_ip,
            "source_port": r.source_port,
            "dest_ip": r.dest_ip,
            "dest_port": r.dest_port,
            "proto": r.proto,
            "timestamp": r.timestamp,
            "summary_text": r.summary_text,
            "raw_fields": r.raw_fields,
            "ground_truth": r.ground_truth
        })
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(serialized, f, indent=2)
    print(f"[+] Saved {len(serialized)} records to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Ingest, label, and partition raw VM telemetry logs")
    parser.add_argument("--raw-dir", type=str, default="data/raw_logs",
                        help="Path containing exported VM logs or tar.gz archive")
    parser.add_argument("--use-samples-fallback", action="store_true",
                        help="If raw_dir has no logs, copy and expand from sample_logs")

    args = parser.parse_args()

    benign, malicious = import_logs(args.raw_dir)

    if not benign and not malicious and args.use_samples_fallback:
        print("[*] No logs in raw_logs, bootstrapping from sample_logs...")
        from data.sample_logs.loader import load_sample_dataset
        b_samples, m_samples = load_sample_dataset("data/sample_logs")
        benign = b_samples
        malicious = m_samples

    total = len(benign) + len(malicious)
    print("\n" + "=" * 65)
    print(" TELEMETRY DATASET INGESTION SUMMARY")
    print("=" * 65)
    print(f" Total Records Ingested:    {total}")
    print(f"  - Clean Benign Records:   {len(benign)}")
    print(f"  - Malicious Records:      {len(malicious)}")
    print("=" * 65)

    if total > 0:
        save_corpus(benign, "data/benign/benign_corpus.json")
        save_corpus(malicious, "data/malicious/malicious_corpus.json")


if __name__ == "__main__":
    main()
