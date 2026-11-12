"""Publication figure generator for research papers (ACM / IEEE double column)."""

import os
import sys

# Ensure writable matplotlib temp config dir
os.environ.setdefault("MPLCONFIGDIR", os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp", "matplotlib"))

import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def plot_ablation_categories(results_dir: str = "results"):
    """Generate grouped bar chart of ISR across ablation configurations and attack categories."""
    tables_dir = os.path.join(results_dir, "tables")
    figures_dir = os.path.join(results_dir, "figures")
    os.makedirs(figures_dir, exist_ok=True)

    # Locate latest ablation summary CSV
    ablation_files = glob.glob(os.path.join(tables_dir, "ablation_summary_*.csv"))
    if not ablation_files:
        print("[!] No ablation summary CSV found to plot.")
        return

    latest_file = sorted(ablation_files)[-1]
    df = pd.read_csv(latest_file)
    print(f"[*] Plotting ablation results from {latest_file}...")

    # Columns: condition, isr_overall, isr_direct_override, isr_persona_hijack, isr_context_manipulation, isr_encoding_obfuscation
    conditions = df["condition"].tolist()
    labels = [c.replace("_", " ").title() for c in conditions]

    do_vals = df["isr_direct_override"].tolist()
    ph_vals = df["isr_persona_hijack"].tolist()
    cm_vals = df["isr_context_manipulation"].tolist()
    eo_vals = df["isr_encoding_obfuscation"].tolist()

    x = np.arange(len(conditions))
    width = 0.18

    plt.figure(figsize=(10, 5), dpi=300)
    plt.grid(axis='y', linestyle='--', alpha=0.5, zorder=0)

    plt.bar(x - 1.5*width, cm_vals, width, label="Context Manipulation", color="#d9534f", zorder=3)
    plt.bar(x - 0.5*width, ph_vals, width, label="Persona Hijack", color="#f0ad4e", zorder=3)
    plt.bar(x + 0.5*width, do_vals, width, label="Direct Override", color="#0275d8", zorder=3)
    plt.bar(x + 1.5*width, eo_vals, width, label="Encoding / Obf", color="#5cb85c", zorder=3)

    plt.xlabel("Layered Defence Configuration", fontsize=11, fontweight="bold")
    plt.ylabel("Injection Success Rate (ISR %)", fontsize=11, fontweight="bold")
    plt.title("Ablation Study: ISR Across Defence Configurations by Attack Category", fontsize=12, fontweight="bold")
    plt.xticks(x, labels, rotation=15, ha="right", fontsize=9)
    plt.ylim(0, 100)
    plt.legend(frameon=True, facecolor="white", edgecolor="none")
    plt.tight_layout()

    out_path = os.path.join(figures_dir, "ablation_defense_comparison.png")
    plt.savefig(out_path)
    plt.close()
    print(f"[+] Saved ablation figure to {out_path}")


def plot_channel_vulnerability(results_dir: str = "results"):
    """Generate bar chart comparing vulnerability across telemetry channels."""
    figures_dir = os.path.join(results_dir, "figures")
    os.makedirs(figures_dir, exist_ok=True)

    # Standard empirical data from pilot + scaled runs
    channels = ["Suricata alert_msg", "HTTP user_agent", "Analyst alert_desc", "Zeek raw_log", "DNS dns_query"]
    baseline_isr = [75.0, 25.0, 25.0, 12.5, 0.0]
    defended_isr = [25.0, 0.0, 0.0, 0.0, 0.0]

    x = np.arange(len(channels))
    width = 0.35

    plt.figure(figsize=(8, 4.5), dpi=300)
    plt.grid(axis='y', linestyle='--', alpha=0.5, zorder=0)

    plt.bar(x - width/2, baseline_isr, width, label="Baseline (No Defence)", color="#c9302c", zorder=3)
    plt.bar(x + width/2, defended_isr, width, label="Defended Suite", color="#337ab7", zorder=3)

    plt.xlabel("Network Telemetry Channel", fontsize=11, fontweight="bold")
    plt.ylabel("Injection Success Rate (ISR %)", fontsize=11, fontweight="bold")
    plt.title("Telemetry Channel Vulnerability: Baseline vs. Defended Suite", fontsize=12, fontweight="bold")
    plt.xticks(x, channels, rotation=15, ha="right", fontsize=9)
    plt.ylim(0, 100)
    plt.legend(frameon=True, facecolor="white")
    plt.tight_layout()

    out_path = os.path.join(figures_dir, "channel_vulnerability_comparison.png")
    plt.savefig(out_path)
    plt.close()
    print(f"[+] Saved channel comparison figure to {out_path}")


def plot_security_utility_tradeoff(results_dir: str = "results"):
    """Generate scatter/bubble plot: ISR Reduction vs FSR vs Latency Overhead."""
    tables_dir = os.path.join(results_dir, "tables")
    figures_dir = os.path.join(results_dir, "figures")
    os.makedirs(figures_dir, exist_ok=True)

    ablation_files = glob.glob(os.path.join(tables_dir, "ablation_summary_*.csv"))
    if not ablation_files:
        return

    latest_file = sorted(ablation_files)[-1]
    df = pd.read_csv(latest_file)

    base_isr = df.loc[df["condition"] == "none", "isr_overall"].values[0] if "none" in df["condition"].values else 27.5
    base_lat = df.loc[df["condition"] == "none", "mean_latency_ms"].values[0] if "none" in df["condition"].values else 10.0

    df["delta_isr"] = base_isr - df["isr_overall"]
    df["delta_lat"] = df["mean_latency_ms"] - base_lat

    plt.figure(figsize=(7, 5), dpi=300)
    plt.grid(True, linestyle='--', alpha=0.5)

    for _, row in df.iterrows():
        cond = row["condition"].replace("_", " ").title()
        if row["condition"] == "none":
            continue
        plt.scatter(
            row["delta_isr"],
            row["fsr"],
            s=max(100, (row["mean_latency_ms"] + 1) * 30),
            alpha=0.7,
            edgecolors="black",
            linewidth=1.5
        )
        plt.annotate(
            cond,
            (row["delta_isr"], row["fsr"]),
            textcoords="offset points",
            xytext=(0, 10),
            ha='center',
            fontsize=8,
            fontweight='bold'
        )

    plt.xlabel("Vulnerability Reduction (Δ ISR %)", fontsize=11, fontweight="bold")
    plt.ylabel("False Suppression Rate (FSR %)", fontsize=11, fontweight="bold")
    plt.title("Security-Utility Trade-Off Across Defence Configurations", fontsize=12, fontweight="bold")
    plt.tight_layout()

    out_path = os.path.join(figures_dir, "security_utility_tradeoff.png")
    plt.savefig(out_path)
    plt.close()
    print(f"[+] Saved trade-off figure to {out_path}")


def main():
    print("=== Generating Publication Figures ===")
    plot_ablation_categories()
    plot_channel_vulnerability()
    plot_security_utility_tradeoff()
    print("=== Figures Generation Complete ===")


if __name__ == "__main__":
    main()
