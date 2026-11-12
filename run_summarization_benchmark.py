"""Command-line runner for Incident Summarization Prompt Injection Benchmark."""

import argparse
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    if os.path.exists('.env'):
        with open('.env', 'r', encoding='utf-8') as _env_f:
            for _line in _env_f:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _k, _v = _line.split('=', 1)
                    os.environ.setdefault(_k.strip(), _v.strip())

from src.copilot.pipeline import NetworkCopilot
from src.attacks.payload_bank import get_curated_payload_bank
from src.attacks.taxonomy import TelemetryChannel, AttackCategory
from src.evaluation.runner import BenchmarkRunner
from src.evaluation.metrics import calculate_summarization_isr
from data.sample_logs.loader import load_sample_dataset


def create_incident_batches(malicious_records, benign_records, batch_size=4):
    """
    Construct multi-record incident batches where each batch contains:
    1 primary malicious record mixed with benign background records.
    """
    batches = []
    for i, mal_rec in enumerate(malicious_records):
        # Pick 2-3 benign records to accompany the malicious record
        start_idx = (i * 2) % max(1, len(benign_records))
        batch = [mal_rec]
        for offset in range(batch_size - 1):
            if benign_records:
                batch.append(benign_records[(start_idx + offset) % len(benign_records)])
        batches.append(batch)
    return batches


def main():
    parser = argparse.ArgumentParser(description="Evaluate Prompt Injection on Multi-Record Incident Summarization")
    parser.add_argument("--model", type=str, default="openai/gpt-oss-20b",
                        help="Model to test (e.g. openai/gpt-oss-20b, qwen/qwen3.8-27b)")
    parser.add_argument("--defences", type=str, default="none",
                        help="Comma-separated defences: none, boundary_awareness, spotlighting, classifier_filter, all")
    parser.add_argument("--channels", type=str, default="all",
                        help="Channels to evaluate: all, alert_msg, user_agent, raw_log, dns_query, alert_desc")
    parser.add_argument("--quick", action="store_true",
                        help="Quick probe mode (1 payload per category)")
    parser.add_argument("--max-incidents", type=int, default=2,
                        help="Number of incident batches to test (default: 2)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay in seconds between requests")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run in offline simulation mode without Groq API calls")

    args = parser.parse_args()

    api_key = os.getenv("GROQ_API_KEY")
    provider = "mock" if args.dry_run else "groq"

    if provider == "groq" and (not api_key or api_key.startswith("gsk_your_groq")):
        print("[!] Error: GROQ_API_KEY is not configured in .env.")
        print("    To run offline simulation mode without an API key, use --dry-run")
        sys.exit(1)

    # Parse defences
    if args.defences.lower() == "none":
        active_defences = []
    elif args.defences.lower() == "all":
        active_defences = ["boundary_awareness", "spotlighting", "classifier_filter"]
    else:
        active_defences = [d.strip() for d in args.defences.split(",") if d.strip()]

    # Parse channels
    if args.channels.lower() == "all":
        channels = list(TelemetryChannel)
    else:
        channel_map = {c.value: c for c in TelemetryChannel}
        channels = [channel_map[c.strip()] for c in args.channels.split(",") if c.strip() in channel_map]

    # Load records and create batches
    benign_logs, malicious_logs = load_sample_dataset("data/sample_logs")
    if args.max_incidents and args.max_incidents > 0:
        malicious_logs = malicious_logs[:args.max_incidents]

    incident_batches = create_incident_batches(malicious_logs, benign_logs, batch_size=4)
    print(f"[*] Prepared {len(incident_batches)} multi-record incident batches for summarization testing.")

    # Load payloads
    all_payloads = get_curated_payload_bank()
    if args.quick:
        seen = set()
        payloads = []
        for p in all_payloads:
            if p.category not in seen:
                payloads.append(p)
                seen.add(p.category)
    else:
        payloads = all_payloads

    print(f"[*] Selected {len(payloads)} payloads across {len(channels)} channels.")
    print(f"[*] Execution Mode: {'OFFLINE SIMULATION (--dry-run)' if args.dry_run else 'LIVE GROQ API'}")

    copilot = NetworkCopilot(
        model_name=args.model,
        provider=provider,
        api_key=api_key,
        defences=active_defences,
        delay_seconds=args.delay
    )

    runner = BenchmarkRunner(output_dir="results")
    results_df = runner.evaluate_summarization_injections(
        copilot=copilot,
        incident_batches=incident_batches,
        payloads=payloads,
        channels=channels,
        experiment_name="eval_summarization"
    )

    summary_stats = calculate_summarization_isr(results_df.to_dict(orient="records"))

    # Print Formatted Results
    print("\n" + "=" * 65)
    print(f" INCIDENT SUMMARIZATION INJECTION RESULTS (Model: {args.model})")
    print(f" Active Defences: {active_defences if active_defences else 'None (Baseline)'}")
    print("=" * 65)
    print(f" Total Incident Batches Tested:    {summary_stats['total']}")
    print(f" Total Successful S-Injections:    {summary_stats['successful_injections']}")
    print(f" Summarization ISR (S-ISR):        {summary_stats['s_isr']}%")
    print(f" ├─ Threat Level Downgrades:       {summary_stats['threat_downgrades']}")
    print(f" ├─ Malicious Detection Suppressed:{summary_stats['malicious_suppressions']}")
    print(f" └─ Narrative Hijacking Occurrences:{summary_stats['narrative_hijacks']}")
    print("=" * 65)


if __name__ == "__main__":
    main()
