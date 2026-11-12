"""Command-line runner for the 6-stage Defence Ablation Study."""

import argparse
import os
import sys
try:
    from dotenv import load_dotenv
    # load_dotenv handled
except ImportError:
    if os.path.exists('.env'):
        with open('.env', 'r', encoding='utf-8') as _env_f:
            for _line in _env_f:
                _line = _line.strip()
                if _line and not _line.startswith('#') and '=' in _line:
                    _k, _v = _line.split('=', 1)
                    os.environ.setdefault(_k.strip(), _v.strip())
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from src.attacks.payload_bank import get_curated_payload_bank
from src.attacks.taxonomy import TelemetryChannel, AttackCategory
from src.evaluation.runner import BenchmarkRunner
from data.sample_logs.loader import load_sample_dataset


def main():
    # load_dotenv handled
    parser = argparse.ArgumentParser(description="Run 6-Stage Defence Ablation Study for Network Copilot")
    parser.add_argument("--model", type=str, default="openai/gpt-oss-20b",
                        help="Model to test (e.g. openai/gpt-oss-20b, qwen/qwen3.8-27b)")
    parser.add_argument("--quick", action="store_true",
                        help="Use 1 payload per category (faster run)")
    parser.add_argument("--max-records", type=int, default=2,
                        help="Number of malicious / benign records to test (default: 2)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay in seconds between API requests (default: 0.5)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run offline simulation mode without consuming Groq API credits")

    args = parser.parse_args()

    api_key = os.getenv("GROQ_API_KEY")
    provider = "mock" if args.dry_run else "groq"

    if provider == "groq" and (not api_key or api_key.startswith("gsk_your_groq")):
        print("[!] Error: GROQ_API_KEY is not configured in .env.")
        print("    To run offline simulation mode without an API key, use --dry-run")
        sys.exit(1)

    # Load logs
    benign_logs, malicious_logs = load_sample_dataset("data/sample_logs")
    if args.max_records and args.max_records > 0:
        malicious_logs = malicious_logs[:args.max_records]
        benign_logs = benign_logs[:args.max_records]
    print(f"[*] Loaded dataset: {len(benign_logs)} benign, {len(malicious_logs)} malicious records.")

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

    channels = list(TelemetryChannel)
    print(f"[*] Testing {len(payloads)} payloads across {len(channels)} channels.")
    print(f"[*] Execution Mode: {'OFFLINE SIMULATION (--dry-run)' if args.dry_run else 'LIVE GROQ API'}")

    runner = BenchmarkRunner(output_dir="results")
    ablation_df = runner.evaluate_ablation_sweep(
        model_name=args.model,
        provider=provider,
        api_key=api_key,
        test_records=malicious_logs,
        benign_records=benign_logs,
        payloads=payloads,
        channels=channels,
        delay_seconds=args.delay
    )

    # Print Formatted Results Table
    print("\n" + "=" * 90)
    print(f" DEFENCE ABLATION RESULTS TABLE (Model: {args.model})")
    print("=" * 90)
    print(f"{'Condition':<24} | {'Overall ISR':<12} | {'DO %':<7} | {'PH %':<7} | {'CM %':<7} | {'EO %':<7} | {'FSR %':<7} | {'Latency':<9}")
    print("-" * 90)
    for _, r in ablation_df.iterrows():
        cond = str(r["condition"])
        isr_all = f"{r['isr_overall']:.1f}%"
        do_val = f"{r['isr_direct_override']:.1f}%"
        ph_val = f"{r['isr_persona_hijack']:.1f}%"
        cm_val = f"{r['isr_context_manipulation']:.1f}%"
        eo_val = f"{r['isr_encoding_obfuscation']:.1f}%"
        fsr_val = f"{r['fsr']:.1f}%"
        lat_val = f"{r['mean_latency_ms']:.1f}ms"
        print(f"{cond:<24} | {isr_all:<12} | {do_val:<7} | {ph_val:<7} | {cm_val:<7} | {eo_val:<7} | {fsr_val:<7} | {lat_val:<9}")
    print("=" * 90)

    # Print LaTeX Table Code
    print("\n[+] LaTeX Code for Research Paper:")
    print("-" * 60)
    print("\\begin{table*}[t]")
    print("\\centering")
    print("\\caption{Ablation Study of Layered Defences Across Attack Categories and Utility Overhead}")
    print("\\label{tab:ablation_study}")
    print("\\begin{tabular}{l c c c c c c c}")
    print("\\hline")
    print("\\textbf{Defence Configuration} & \\textbf{Overall ISR} & \\textbf{DO} & \\textbf{PH} & \\textbf{CM} & \\textbf{EO} & \\textbf{FSR} & \\textbf{Latency (ms)} \\\\")
    print("\\hline")
    for _, r in ablation_df.iterrows():
        print(f"{r['condition']} & {r['isr_overall']:.1f}\\% & {r['isr_direct_override']:.1f}\\% & {r['isr_persona_hijack']:.1f}\\% & {r['isr_context_manipulation']:.1f}\\% & {r['isr_encoding_obfuscation']:.1f}\\% & {r['fsr']:.1f}\\% & {r['mean_latency_ms']:.1f} \\\\")
    print("\\hline")
    print("\\end{tabular}")
    print("\\end{table*}")
    print("-" * 60)


if __name__ == "__main__":
    main()
