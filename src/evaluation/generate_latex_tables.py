"""Automated LaTeX table generator for research papers (ACM AISec / IEEE Access)."""

import os
import sys
import glob
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def generate_ablation_latex(results_dir: str = "results", out_file: str = "results/tables/table_ablation.tex"):
    """Convert latest ablation summary CSV to publication-ready LaTeX table."""
    tables_dir = os.path.join(results_dir, "tables")
    ablation_files = glob.glob(os.path.join(tables_dir, "ablation_summary_*.csv"))
    if not ablation_files:
        print("[!] No ablation summary CSV found.")
        return

    latest_file = sorted(ablation_files)[-1]
    df = pd.read_csv(latest_file)

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Ablation Study: Empirical Injection Success Rate (ISR), False Suppression Rate (FSR), and Latency Overhead Across Layered Defences}",
        r"\label{tab:ablation_results}",
        r"\begin{tabular}{l c c c c c c c}",
        r"\hline\hline",
        r"\textbf{Defence Configuration} & \textbf{Overall ISR (\%)} & \textbf{Direct Override} & \textbf{Persona Hijack} & \textbf{Context Manip.} & \textbf{Encoding/Obf.} & \textbf{FSR (\%)} & \textbf{Latency (ms)} \\",
        r"\hline"
    ]

    for _, r in df.iterrows():
        cond_label = str(r["condition"]).replace("_", " ").title()
        overall = f"{r['isr_overall']:.1f}\\%"
        do_val = f"{r['isr_direct_override']:.1f}\\%"
        ph_val = f"{r['isr_persona_hijack']:.1f}\\%"
        cm_val = f"{r['isr_context_manipulation']:.1f}\\%"
        eo_val = f"{r['isr_encoding_obfuscation']:.1f}\\%"
        fsr_val = f"{r['fsr']:.1f}\\%"
        lat_val = f"{r['mean_latency_ms']:.1f}"

        lines.append(f"{cond_label} & {overall} & {do_val} & {ph_val} & {cm_val} & {eo_val} & {fsr_val} & {lat_val} \\\\")

    lines.extend([
        r"\hline\hline",
        r"\end{tabular}",
        r"\end{table*}"
    ])

    tex_content = "\n".join(lines)
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(tex_content)
    print(f"[+] Generated ablation LaTeX table: {out_file}")
    return tex_content


def generate_summarization_latex(results_dir: str = "results", out_file: str = "results/tables/table_summarization.tex"):
    """Convert latest summarization CSV to publication-ready LaTeX table."""
    tables_dir = os.path.join(results_dir, "tables")
    sum_files = glob.glob(os.path.join(tables_dir, "eval_summarization_*.csv"))
    if not sum_files:
        print("[!] No summarization CSV found.")
        return

    latest_file = sorted(sum_files)[-1]
    df = pd.read_csv(latest_file)

    total = len(df)
    threat_down = int(df["threat_downgraded"].sum()) if "threat_downgraded" in df.columns else 0
    mal_supp = int(df["malicious_suppressed"].sum()) if "malicious_suppressed" in df.columns else 0
    narr_hij = int(df["narrative_hijacked"].sum()) if "narrative_hijacked" in df.columns else 0
    total_succ = int(df["is_injection_success"].sum()) if "is_injection_success" in df.columns else 0

    s_isr = (total_succ / total) * 100.0 if total > 0 else 0.0

    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Empirical Robustness of Multi-Record Incident Summarization Under Telemetry Prompt Injection}",
        r"\label{tab:summarization_results}",
        r"\begin{tabular}{l c c}",
        r"\hline\hline",
        r"\textbf{Summarization Failure Metric} & \textbf{Count (N=" + str(total) + r")} & \textbf{Rate (\%)} \\",
        r"\hline",
        f"Threat Level Downgrade (High $\\rightarrow$ Low/None) & {threat_down} & {(threat_down/total)*100:.1f}\\% \\\\",
        f"Malicious Detection Suppression & {mal_supp} & {(mal_supp/total)*100:.1f}\\% \\\\",
        f"Operational Narrative Hijacking & {narr_hij} & {(narr_hij/total)*100:.1f}\\% \\\\",
        r"\hline",
        f"\\textbf{{Overall Summarization ISR (S-ISR)}} & \\textbf{{{total_succ}}} & \\textbf{{{s_isr:.1f}\\%}} \\\\",
        r"\hline\hline",
        r"\end{tabular}",
        r"\end{table}"
    ]

    tex_content = "\n".join(lines)
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(tex_content)
    print(f"[+] Generated summarization LaTeX table: {out_file}")
    return tex_content


def main():
    print("=== Generating LaTeX Publication Tables ===")
    generate_ablation_latex()
    generate_summarization_latex()
    print("=== LaTeX Tables Generation Complete ===")


if __name__ == "__main__":
    main()
