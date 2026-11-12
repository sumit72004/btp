# Adversarial Robustness of LLM-Based Network Monitoring Copilots

**B.Tech Thesis Project (7th Semester)**  
**Authors:** Sumit Kumar (2023UIT3060), Nitish Kumar Sah (2023UIT3039), Anand Kumar (2023UIT3061)  
**Supervisor:** Dr. Nisha Kandhoul  

---

## 📌 Project Overview
This repository contains the evaluation framework, telemetry parsers, attack corpus, sanitization defences, and experimental benchmark harness for investigating **Indirect Prompt Injection** vulnerabilities in LLM-based network security copilots ingesting Zeek and Suricata telemetry.

### Research Questions
- **RQ1 (Exploitability):** Can prompt-injection payloads embedded in network telemetry manipulate classification or summarization decisions?
- **RQ2 (Channel Vulnerability & Scale):** Which network channels (`user_agent`, `dns_query`, `alert_msg`, `raw_log`) are most susceptible, and does susceptibility vary across model architectures (Llama, Mistral/Mixtral, Gemma)?
- **RQ3 (Defences & Utility Cost):** How effectively do Boundary-Awareness, Spotlighting (data-marking), and Pre-filters mitigate injection, and what are their costs in False Suppression Rate (FSR) and latency overhead?

---

## 🚀 Quick Start (Windows Host)

### 1. Configure API Key
Sign up for a free key at [Groq Console](https://console.groq.com) and add it to your `.env` file:
```env
GROQ_API_KEY=gsk_your_actual_key_here
```

### 2. Verify Pipeline (Smoke Test)
Run the end-to-end smoke test to verify parsers and LLM inference:
```bash
python quick_test.py
```

### 3. Run Experiments

#### Baseline and Custom Defence Sweeps
Execute a quick injection test without defences (baseline):
```bash
python run_benchmark.py --model openai/gpt-oss-20b --defences none --quick
```

#### Systematic 6-Stage Defence Ablation Study (RQ3)
Automatically evaluate across all 6 configurations (Baseline, Boundary, Spotlighting, Pre-Filter, In-Context, and Full Layered Suite):
```bash
# Live API benchmark
python run_ablation.py --model openai/gpt-oss-20b

# Fast smoke-test or offline simulation mode
python run_ablation.py --model openai/gpt-oss-20b --quick --dry-run
```

#### Multi-Record Incident Summarization Benchmark (RQ1 / RQ2)
Evaluate prompt-injection robustness against multi-record incident summaries:
```bash
# Baseline summarization injection
python run_summarization_benchmark.py --model openai/gpt-oss-20b --defences none

# Defended summarization injection
python run_summarization_benchmark.py --model openai/gpt-oss-20b --defences all
```

#### Ingest and Partition Live VMware Testbed Logs
Extract and label exported Zeek (`conn`, `http`, `dns`) and Suricata (`eve.json`) logs:
```bash
python data/import_vm_logs.py --raw-dir data/raw_logs
```

#### Generate Publication Figures and LaTeX Tables
Generate publication-quality figures and double-column LaTeX tables for IEEE/ACM formats:
```bash
# High-DPI Figures (Ablation, Channel vulnerability, Security-Utility trade-off)
python src/evaluation/generate_figures.py

# Publication LaTeX Tables (\begin{table*} ... \end{table*})
python src/evaluation/generate_latex_tables.py
```

---

## 🖥️ VMware Ubuntu Testbed Setup

To generate realistic live Zeek and Suricata logs from your Ubuntu VM:

1. **Copy `testbed/` to your Ubuntu VM.**
2. **Run setup script:**
   ```bash
   chmod +x testbed/setup_vm.sh testbed/export_logs.sh
   ./testbed/setup_vm.sh
   ```
3. **Generate benign and malicious traffic:**
   ```bash
   sudo python3 testbed/generate_traffic.py
   ```
4. **Export logs:**
   ```bash
   ./testbed/export_logs.sh
   ```
5. Copy the generated `.tar.gz` archive back to `data/raw_logs/` on Windows.

---

## 📂 Repository Layout
```
├── configs/                 # Prompt configs and experiment manifests
├── src/
│   ├── copilot/             # Network copilot pipeline, parsers, prompts
│   │   ├── pipeline.py
│   │   ├── prompt_templates.py
│   │   └── log_parsers.py
│   ├── attacks/             # Attack taxonomy, payload bank, generators
│   │   ├── taxonomy.py
│   │   ├── payload_bank.py
│   │   └── generators.py
│   ├── defences/            # Sanitization & isolation defences
│   │   ├── boundary_awareness.py
│   │   ├── spotlighting.py
│   │   └── classifier_filter.py
│   └── evaluation/          # Metrics (ISR, FSR, Latency, Significance)
│       ├── metrics.py
│       ├── runner.py
│       ├── generate_figures.py
│       └── generate_latex_tables.py
├── data/
│   ├── sample_logs/         # Built-in sample Zeek and Suricata datasets
│   ├── raw_logs/            # Exported VM logs
│   ├── benign/              # Clean benign ground truth
│   ├── malicious/           # Clean attack ground truth
│   └── import_vm_logs.py    # Scaled VM log parser & labeler
├── testbed/                 # VM setup and traffic simulation scripts
├── results/
│   ├── tables/              # CSV, JSON, and LaTeX benchmark results
│   └── figures/             # Generated plots and heatmaps
├── quick_test.py            # Quick verification script
├── run_benchmark.py         # Automated CLI experiment runner
├── run_ablation.py          # 6-Stage defence ablation study runner
├── run_summarization_benchmark.py # Incident summarization benchmark
└── requirements.txt         # Project dependencies
```
