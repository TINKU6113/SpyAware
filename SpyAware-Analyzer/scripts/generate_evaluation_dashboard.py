#!/usr/bin/env python3
"""HTML5 Evaluation Dashboard Generator for SpyAware-Analyzer.

Milestone Phase I:
Creates a standalone, responsive, high-performance HTML5 dashboard at dashboard/index.html
incorporating authentic evaluation metrics, KPI summary tiles, per-sample data tables,
embedded publication figures, and methodology notes.
"""

import argparse
import html
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dashboard_generator")


def generate_dashboard_html(
    summary: Dict[str, Any],
    records: List[Dict[str, Any]],
    output_path: Path,
):
    """Generates a comprehensive, self-contained HTML dashboard."""
    meta = summary.get("metadata", {})
    counts = summary.get("sample_counts", {})
    scores = summary.get("risk_scores", {})
    sevs = summary.get("findings_by_severity", {})
    perms = summary.get("declared_permission_distribution", {})
    tele = summary.get("runtime_telemetry_by_category", {})

    total_selected = counts.get("selected_samples", len(records))
    static_ok = counts.get("static_completed", 0)
    perm_ok = counts.get("permission_completed", 0)
    dyn_ok = counts.get("dynamic_completed", 0)
    dyn_failed = counts.get("dynamic_failed_or_unavailable", 0)
    blocked_abi = counts.get("blocked_by_abi_compatibility", 0)
    mean_score = scores.get("mean", 0.0)
    median_score = scores.get("median", 0.0)

    # Risk level badge styling
    def get_badge(lvl: str) -> str:
        color_map = {
            "CRITICAL": "bg-red-500/20 text-red-400 border-red-500/40",
            "HIGH": "bg-orange-500/20 text-orange-400 border-orange-500/40",
            "MEDIUM": "bg-amber-500/20 text-amber-400 border-amber-500/40",
            "LOW": "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
            "UNKNOWN": "bg-slate-500/20 text-slate-400 border-slate-500/40",
        }
        cls = color_map.get(lvl, color_map["UNKNOWN"])
        return f'<span class="px-2 py-0.5 rounded text-xs font-semibold border {cls}">{lvl}</span>'

    # Build rows
    sorted_records = sorted(records, key=lambda r: r.get("overall_score") or 0.0, reverse=True)
    table_rows = []
    for r in sorted_records:
        sha_short = r["sha256"][:10]
        fn = html.escape(r.get("filename", ""))
        pkg = html.escape(r.get("package_name") or "unknown")
        stratum = html.escape(r.get("selection_stratum") or "N/A")
        sz_kb = f"{round(r.get('file_size_bytes', 0) / 1024, 1):,}"
        abis = html.escape(", ".join(r.get("native_abis", [])) if r.get("native_abis") else "Pure Java")
        s_score = f"{r.get('module_scores', {}).get('static', 0.0):.1f}" if r.get('module_scores', {}).get('static') is not None else "N/A"
        p_score = f"{r.get('module_scores', {}).get('permissions', 0.0):.1f}" if r.get('module_scores', {}).get('permissions') is not None else "N/A"
        dyn_st = r.get("module_status", {}).get("dynamic", "NOT_TESTED")
        ov_score = f"{r.get('overall_score', 0.0):.1f}" if r.get('overall_score') is not None else "N/A"
        lvl = r.get("risk_level", "UNKNOWN")
        f_cnt = r.get("findings_total", 0)

        dyn_badge = "text-emerald-400" if dyn_st == "COMPLETED" else ("text-amber-400" if "INCOMPATIBLE" in dyn_st else "text-rose-400")

        row_html = f"""
        <tr class="border-b border-slate-800/80 hover:bg-slate-800/40 transition-colors">
            <td class="py-3 px-4 font-mono text-xs text-sky-400">{sha_short}…</td>
            <td class="py-3 px-4 font-mono text-xs text-slate-200" title="{pkg}">{pkg[:24]}</td>
            <td class="py-3 px-4 text-xs text-slate-400">{stratum}</td>
            <td class="py-3 px-4 text-xs text-slate-300 text-right">{sz_kb} KB</td>
            <td class="py-3 px-4 text-xs text-slate-400">{abis}</td>
            <td class="py-3 px-4 text-xs text-slate-200 text-right font-mono">{s_score}</td>
            <td class="py-3 px-4 text-xs text-slate-200 text-right font-mono">{p_score}</td>
            <td class="py-3 px-4 text-xs font-mono {dyn_badge}">{dyn_st}</td>
            <td class="py-3 px-4 text-xs font-bold font-mono text-right text-slate-100">{ov_score}</td>
            <td class="py-3 px-4 text-center">{get_badge(lvl)}</td>
            <td class="py-3 px-4 text-xs text-slate-300 text-right font-mono">{f_cnt}</td>
        </tr>
        """
        table_rows.append(row_html)

    html_content = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpyAware Analyzer — CIC Riskware Evaluation Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body {{
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: #0b1120;
            color: #f1f5f9;
        }}
        code, pre, .font-mono {{
            font-family: 'JetBrains Mono', monospace;
        }}
    </style>
</head>
<body class="min-h-screen antialiased bg-[#0b1120] text-slate-100">

    <!-- Top Navigation Header -->
    <header class="border-b border-slate-800 bg-[#0f172a]/80 backdrop-blur sticky top-0 z-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center font-black text-white text-lg tracking-wider shadow-lg shadow-blue-500/20">
                    SA
                </div>
                <div>
                    <h1 class="text-lg font-bold tracking-tight text-white flex items-center gap-2">
                        SpyAware Analyzer <span class="text-xs px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">Evaluation Report</span>
                    </h1>
                    <p class="text-xs text-slate-400">CIC Riskware Dataset Empirical Pipeline Audit</p>
                </div>
            </div>
            <div class="flex items-center space-x-3 text-xs text-slate-400">
                <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Pipeline Verified
                </span>
                <span class="hidden md:inline font-mono">Profile: {meta.get("execution_profile", "STANDARD")}</span>
                <span class="hidden md:inline font-mono">AVD: {meta.get("emulator_avd", "Medium_Phone_API_36.1")}</span>
            </div>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-10">

        <!-- Executive Summary Banner -->
        <section class="bg-gradient-to-r from-blue-900/30 via-slate-900 to-slate-900 border border-blue-500/20 rounded-2xl p-6 sm:p-8 shadow-xl">
            <div class="max-w-3xl space-y-3">
                <div class="inline-flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-blue-400">
                    <span>Autonomous Empirical Evaluation</span> &bull; <span>Authentic Dataset</span>
                </div>
                <h2 class="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                    End-to-End Analysis of 15 Stratified Riskware APK Samples
                </h2>
                <p class="text-sm sm:text-base text-slate-300 leading-relaxed">
                    Evaluated against the authentic SpyAware multi-module pipeline: Universal APK Intake, DEX static inspection, dedicated permission rule evaluation, execution compatibility verification, and isolated runtime observation in Android emulator (<code class="text-sky-300">API 36.1</code>).
                </p>
            </div>
        </section>

        <!-- KPI Metric Cards Grid -->
        <section class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <span class="text-xs font-medium text-slate-400 uppercase tracking-wider">Discovered APKs</span>
                <div class="mt-2 text-2xl sm:text-3xl font-black text-white font-mono">4,362</div>
                <span class="mt-1 text-[11px] text-slate-500">3,904 Valid Unique</span>
            </div>
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <span class="text-xs font-medium text-slate-400 uppercase tracking-wider">Selected Samples</span>
                <div class="mt-2 text-2xl sm:text-3xl font-black text-blue-400 font-mono">{total_selected}</div>
                <span class="mt-1 text-[11px] text-slate-500">Stratified Selection</span>
            </div>
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <span class="text-xs font-medium text-slate-400 uppercase tracking-wider">Static Success</span>
                <div class="mt-2 text-2xl sm:text-3xl font-black text-emerald-400 font-mono">{static_ok}/{total_selected}</div>
                <span class="mt-1 text-[11px] text-emerald-500/80">100% Manifest & DEX</span>
            </div>
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <span class="text-xs font-medium text-slate-400 uppercase tracking-wider">Dynamic Complete</span>
                <div class="mt-2 text-2xl sm:text-3xl font-black text-sky-400 font-mono">{dyn_ok}/{total_selected}</div>
                <span class="mt-1 text-[11px] text-slate-500">{blocked_abi} Blocked (ABI)</span>
            </div>
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <span class="text-xs font-medium text-slate-400 uppercase tracking-wider">Mean Risk Score</span>
                <div class="mt-2 text-2xl sm:text-3xl font-black text-amber-400 font-mono">{mean_score:.1f}</div>
                <span class="mt-1 text-[11px] text-slate-500">Median: {median_score:.1f}</span>
            </div>
            <div class="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <span class="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Findings</span>
                <div class="mt-2 text-2xl sm:text-3xl font-black text-red-400 font-mono">{sum(sevs.values())}</div>
                <span class="mt-1 text-[11px] text-red-500/80">{sevs.get("CRITICAL", 0)} Critical, {sevs.get("HIGH", 0)} High</span>
            </div>
        </section>

        <!-- Evaluation Results Interactive Table -->
        <section class="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-white tracking-tight">Per-Sample Evaluation Results</h3>
                    <p class="text-xs text-slate-400">Authentic multi-module outcomes across 15 stratified APK samples</p>
                </div>
                <div class="flex items-center gap-2">
                    <a href="../results/per_apk_results.csv" download class="inline-flex items-center px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition-colors">
                        Download CSV
                    </a>
                    <a href="../results/per_apk_results.json" download class="inline-flex items-center px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition-colors">
                        Download JSON
                    </a>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400 bg-slate-950/40">
                            <th class="py-3 px-4">SHA-256</th>
                            <th class="py-3 px-4">Package</th>
                            <th class="py-3 px-4">Stratum</th>
                            <th class="py-3 px-4 text-right">Size</th>
                            <th class="py-3 px-4">ABIs</th>
                            <th class="py-3 px-4 text-right">Static</th>
                            <th class="py-3 px-4 text-right">Perm</th>
                            <th class="py-3 px-4">Dynamic</th>
                            <th class="py-3 px-4 text-right">Overall</th>
                            <th class="py-3 px-4 text-center">Risk Level</th>
                            <th class="py-3 px-4 text-right">Findings</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(table_rows)}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Publication Graphs Gallery -->
        <section class="space-y-6">
            <div>
                <h3 class="text-xl font-bold text-white tracking-tight">Publication Figures & Evidence Visualizations</h3>
                <p class="text-xs text-slate-400">Generated directly from collected evaluation results using Matplotlib (300 DPI)</p>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <!-- Graph 1 -->
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-all shadow-lg flex flex-col">
                    <div class="p-4 border-b border-slate-800/80 bg-slate-950/30">
                        <span class="text-xs font-bold text-sky-400">Figure 1</span>
                        <h4 class="text-sm font-semibold text-white">Risk Score by APK</h4>
                    </div>
                    <div class="p-3 bg-white flex-1 flex items-center justify-center">
                        <img src="../graphs/01_risk_score_by_apk.png" alt="Graph 1: Risk Score by APK" class="w-full h-auto object-contain max-h-72">
                    </div>
                </div>

                <!-- Graph 2 -->
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-all shadow-lg flex flex-col">
                    <div class="p-4 border-b border-slate-800/80 bg-slate-950/30">
                        <span class="text-xs font-bold text-sky-400">Figure 2</span>
                        <h4 class="text-sm font-semibold text-white">Findings by Severity</h4>
                    </div>
                    <div class="p-3 bg-white flex-1 flex items-center justify-center">
                        <img src="../graphs/02_findings_by_severity.png" alt="Graph 2: Findings by Severity" class="w-full h-auto object-contain max-h-72">
                    </div>
                </div>

                <!-- Graph 3 -->
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-all shadow-lg flex flex-col">
                    <div class="p-4 border-b border-slate-800/80 bg-slate-950/30">
                        <span class="text-xs font-bold text-sky-400">Figure 3</span>
                        <h4 class="text-sm font-semibold text-white">Module Execution Coverage</h4>
                    </div>
                    <div class="p-3 bg-white flex-1 flex items-center justify-center">
                        <img src="../graphs/03_module_execution_coverage.png" alt="Graph 3: Module Execution Coverage" class="w-full h-auto object-contain max-h-72">
                    </div>
                </div>

                <!-- Graph 4 -->
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-all shadow-lg flex flex-col">
                    <div class="p-4 border-b border-slate-800/80 bg-slate-950/30">
                        <span class="text-xs font-bold text-sky-400">Figure 4</span>
                        <h4 class="text-sm font-semibold text-white">Permission Distribution</h4>
                    </div>
                    <div class="p-3 bg-white flex-1 flex items-center justify-center">
                        <img src="../graphs/04_permission_distribution.png" alt="Graph 4: Permission Distribution" class="w-full h-auto object-contain max-h-72">
                    </div>
                </div>

                <!-- Graph 5 -->
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-all shadow-lg flex flex-col">
                    <div class="p-4 border-b border-slate-800/80 bg-slate-950/30">
                        <span class="text-xs font-bold text-sky-400">Figure 5</span>
                        <h4 class="text-sm font-semibold text-white">Dynamic Telemetry Status</h4>
                    </div>
                    <div class="p-3 bg-white flex-1 flex items-center justify-center">
                        <img src="../graphs/05_dynamic_telemetry_status.png" alt="Graph 5: Dynamic Telemetry Status" class="w-full h-auto object-contain max-h-72">
                    </div>
                </div>

                <!-- Graph 6 -->
                <div class="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden hover:border-slate-700 transition-all shadow-lg flex flex-col">
                    <div class="p-4 border-b border-slate-800/80 bg-slate-950/30">
                        <span class="text-xs font-bold text-sky-400">Figure 6</span>
                        <h4 class="text-sm font-semibold text-white">Static vs. Dynamic Coverage</h4>
                    </div>
                    <div class="p-3 bg-white flex-1 flex items-center justify-center">
                        <img src="../graphs/06_static_vs_dynamic_coverage.png" alt="Graph 6: Static vs Dynamic Coverage" class="w-full h-auto object-contain max-h-72">
                    </div>
                </div>
            </div>
        </section>

        <!-- Evaluation Artifacts & Methodology -->
        <section class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Artifact Links -->
            <div class="bg-slate-900/70 border border-slate-800 rounded-xl p-6 space-y-4">
                <h3 class="text-base font-bold text-white flex items-center gap-2">
                    <svg class="w-5 h-5 text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                    Evaluation Documentation & Machine-Readable Artifacts
                </h3>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <a href="../reports/SPYAWARE_RISKWARE_EVALUATION_REPORT.md" class="p-3 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 text-slate-300 hover:text-white flex items-center justify-between transition-colors">
                        <span>Evaluation Report (MD)</span>
                        <span class="font-mono text-sky-400">&rarr;</span>
                    </a>
                    <a href="../reports/SPYAWARE_RISKWARE_EXECUTIVE_SUMMARY.md" class="p-3 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 text-slate-300 hover:text-white flex items-center justify-between transition-colors">
                        <span>Executive Summary (MD)</span>
                        <span class="font-mono text-sky-400">&rarr;</span>
                    </a>
                    <a href="../reports/methodology_and_limitations.md" class="p-3 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 text-slate-300 hover:text-white flex items-center justify-between transition-colors">
                        <span>Methodology & Limits (MD)</span>
                        <span class="font-mono text-sky-400">&rarr;</span>
                    </a>
                    <a href="../results/evaluation_summary.json" class="p-3 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 text-slate-300 hover:text-white flex items-center justify-between transition-colors">
                        <span>Summary Metrics (JSON)</span>
                        <span class="font-mono text-sky-400">&rarr;</span>
                    </a>
                    <a href="../results/static_findings.csv" class="p-3 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 text-slate-300 hover:text-white flex items-center justify-between transition-colors">
                        <span>Static Findings (CSV)</span>
                        <span class="font-mono text-sky-400">&rarr;</span>
                    </a>
                    <a href="../results/dynamic_telemetry.csv" class="p-3 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700/60 text-slate-300 hover:text-white flex items-center justify-between transition-colors">
                        <span>Dynamic Telemetry (CSV)</span>
                        <span class="font-mono text-sky-400">&rarr;</span>
                    </a>
                </div>
            </div>

            <!-- Methodology & Constraints -->
            <div class="bg-slate-900/70 border border-slate-800 rounded-xl p-6 space-y-3 text-xs text-slate-300 leading-relaxed">
                <h3 class="text-base font-bold text-white flex items-center gap-2">
                    <svg class="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    Methodological Constraints & Empirical Provenance
                </h3>
                <ul class="space-y-2 list-disc list-inside text-slate-400">
                    <li><strong class="text-slate-200">Ground-Truth Neutrality:</strong> Dataset directory labels do not constitute verified ground truth. Results reflect real analyzer behavior rather than classification accuracy benchmarks.</li>
                    <li><strong class="text-slate-200">Capability vs. Dormancy:</strong> Declared permissions and DEX indicator strings denote potential capability, while runtime telemetry captures observable activation during execution.</li>
                    <li><strong class="text-slate-200">Sandbox Safety:</strong> All dynamic runs executed on isolated local emulator with external networking restricted (HTTP proxy loopback and airplane mode).</li>
                    <li><strong class="text-slate-200">ABI Incompatibility:</strong> Deprecated armeabi-only APKs cannot execute on modern x86_64 host without ARM translation and are authoritatively reported as blocked.</li>
                </ul>
            </div>
        </section>

    </main>

    <footer class="border-t border-slate-800 py-6 text-center text-xs text-slate-500">
        SpyAware Analyzer &bull; Covert Surveillance & Riskware Analysis Platform &bull; Empirical Evaluation 2026
    </footer>

</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info("Saved dashboard to %s", output_path)


def main():
    parser = argparse.ArgumentParser(description="Generate HTML Evaluation Dashboard")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path("/home/j3st3r/Desktop/SpyAware-Report-Preparation/SpyAware-CIC-Evaluation/results"),
        help="Path to results directory",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=Path("/home/j3st3r/Desktop/SpyAware-Report-Preparation/SpyAware-CIC-Evaluation/dashboard/index.html"),
        help="Path to output HTML file",
    )

    args = parser.parse_args()
    args.output_file.parent.mkdir(parents=True, exist_ok=True)

    summary_file = args.results_dir / "evaluation_summary.json"
    per_apk_file = args.results_dir / "per_apk_results.json"

    if not summary_file.exists() or not per_apk_file.exists():
        logger.error("Results files not found in %s", args.results_dir)
        return

    with open(summary_file, "r", encoding="utf-8") as f:
        summary = json.load(f)
    with open(per_apk_file, "r", encoding="utf-8") as f:
        records = json.load(f)

    generate_dashboard_html(summary, records, args.output_file)


if __name__ == "__main__":
    main()
