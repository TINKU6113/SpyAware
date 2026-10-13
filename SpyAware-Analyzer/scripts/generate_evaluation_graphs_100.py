#!/usr/bin/env python3
"""Evaluation Results Visualization Generator for 100-Sample SpyAware-Analyzer Evaluation.

Generates 8 publication-grade, high-resolution (300 DPI) figures using Matplotlib
(strictly without Seaborn) directly from authentic validated output records:

1. 01_risk_score_by_apk.png: Overall aggregate risk score per evaluated sample (100 samples)
2. 02_risk_classification_distribution.png: Risk classification distribution with thresholds, counts, and %
3. 03_findings_by_severity.png: Total and sample distribution of security findings by severity band
4. 04_module_execution_coverage.png: Completed, unavailable, and untested module execution coverage (N=100)
5. 05_dynamic_execution_outcomes.png: Precise dynamic sandbox outcomes (OBSERVED, BLOCKED_ABI, NOT_TESTED_NO_LAUNCHER, FAILED_INSTALL, FAILED_LAUNCH, FAILED_OBSERVATION, UNAVAILABLE)
6. 06_sensitive_permission_distribution.png: Declared Android permission volume and surveillance category footprint
7. 07_static_vs_dynamic_comparison.png: Static score vs Dynamic score for genuinely usable dynamic observations
8. 08_risk_score_distribution.png: Risk score distribution histogram across bounded 0-100 risk bands
"""

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("graph_gen_100")

# Professional cybersecurity report color palette
COLOR_CRITICAL = "#dc2626"  # Red
COLOR_HIGH = "#ea580c"      # Orange
COLOR_MEDIUM = "#ca8a04"    # Goldenrod / Amber
COLOR_LOW = "#16a34a"       # Forest green
COLOR_INFO = "#0284c7"      # Sky blue
COLOR_MUTED = "#64748b"     # Slate gray
COLOR_DARK = "#0f172a"      # Navy dark
COLOR_BG = "#f8fafc"        # Off-white bg
COLOR_ACCENT = "#2563eb"    # Royal blue


def setup_plot_style():
    """Sets clean typography and presentation defaults."""
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "axes.labelsize": 10,
        "axes.labelweight": "bold",
        "xtick.labelsize": 8.5,
        "ytick.labelsize": 8.5,
        "figure.titlesize": 13,
        "figure.titleweight": "bold",
        "figure.dpi": 300,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "axes.grid": True,
        "grid.color": "#e2e8f0",
        "grid.linestyle": "--",
        "grid.alpha": 0.7,
        "axes.facecolor": "#ffffff",
        "figure.facecolor": COLOR_BG,
    })


def graph_01_risk_score_by_apk(records: List[Dict[str, Any]], output_path: Path):
    """GRAPH 1: Risk score by APK across all 100 samples."""
    fig, ax = plt.subplots(figsize=(18, 7))

    sorted_records = sorted(records, key=lambda r: r.get("overall_score") or 0.0, reverse=True)
    scores = [r.get("overall_score") or 0.0 for r in sorted_records]
    levels = [r.get("risk_level", "UNKNOWN") for r in sorted_records]

    bar_colors = []
    for lvl in levels:
        if lvl == "CRITICAL":
            bar_colors.append(COLOR_CRITICAL)
        elif lvl == "HIGH":
            bar_colors.append(COLOR_HIGH)
        elif lvl == "MEDIUM":
            bar_colors.append(COLOR_MEDIUM)
        elif lvl == "LOW":
            bar_colors.append(COLOR_LOW)
        else:
            bar_colors.append(COLOR_MUTED)

    x = np.arange(len(sorted_records))
    bars = ax.bar(x, scores, color=bar_colors, edgecolor="#334155", linewidth=0.4, width=0.7)

    ax.set_ylabel("Overall Risk Score (0–100 Bounded Scale)", fontweight="bold")
    ax.set_xlabel("Analyzed Application Samples (100 Stratified APKs, Sorted by Risk Score)", fontweight="bold")
    ax.set_title("Graph 1: SpyAware Aggregate Risk Score by Evaluated APK Sample (N = 100)", pad=15)
    plt.suptitle("Multi-Module Peak-and-Mean Bounded Score Calculation [0.60·max(S) + 0.40·mean(S)] Across 100 Samples",
                 fontsize=9.5, style="italic", y=0.93, color="#475569")

    # Sample identifiers: show index and SHA256 prefix every 5 samples or rotated
    labels = [f"#{r.get('sample_index', i+1)} {r['sha256'][:6]}" for i, r in enumerate(sorted_records)]
    ax.set_xticks(x[::2])
    ax.set_xticklabels(labels[::2], rotation=90, fontsize=6.5)
    ax.set_ylim(0, 108)

    # Threshold horizontal reference bands
    ax.axhline(75, color=COLOR_CRITICAL, linestyle=":", alpha=0.7, label="Critical Threshold (>=75)")
    ax.axhline(50, color=COLOR_HIGH, linestyle=":", alpha=0.7, label="High Threshold (>=50)")
    ax.axhline(25, color=COLOR_MEDIUM, linestyle=":", alpha=0.7, label="Medium Threshold (>=25)")

    ax.legend(loc="upper right", framealpha=0.9, fontsize=8.5)
    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_02_risk_classification_distribution(summary: Dict[str, Any], output_path: Path):
    """GRAPH 2: Risk classification distribution."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5.5), gridspec_kw={"width_ratios": [1.1, 1]})

    dist = summary.get("risk_scores", {}).get("risk_classification_distribution", {})
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    labels = ["Critical (75–100)", "High (50–74)", "Medium (25–49)", "Low (0–24)"]
    colors = [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW]
    counts = [dist.get(k, 0) for k in order]
    total = sum(counts) if sum(counts) > 0 else 100
    percentages = [(c / total) * 100 for c in counts]

    # Bar chart
    bars = ax1.bar(order, counts, color=colors, edgecolor="#334155", linewidth=0.8, width=0.55)
    ax1.set_ylabel("Number of Samples", fontweight="bold")
    ax1.set_title("Sample Counts by Risk Classification Band", pad=12)
    ax1.set_ylim(0, max(counts) * 1.2 if max(counts) > 0 else 10)

    for bar, c, p in zip(bars, counts, percentages):
        ax1.annotate(
            f"{c} ({p:.1f}%)",
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=9,
        )

    # Donut chart
    wedges, texts, autotexts = ax2.pie(
        counts,
        labels=labels,
        autopct="%1.1f%%",
        startangle=140,
        colors=colors,
        wedgeprops=dict(width=0.45, edgecolor="#ffffff", linewidth=1.5),
        pctdistance=0.75,
        textprops=dict(fontsize=8.5, fontweight="bold"),
    )
    ax2.set_title("Proportional Distribution (% of N=100)", pad=12)

    plt.suptitle("Graph 2: Risk Classification Distribution and Severity Threshold Alignment",
                 fontsize=13, fontweight="bold", y=0.98)
    fig.text(0.5, 0.92, "Thresholds Implemented in RiskEngine: Low (0–24), Medium (25–49), High (50–74), Critical (75–100)",
             ha="center", fontsize=8.5, style="italic", color="#475569")

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_03_findings_by_severity(summary: Dict[str, Any], records: List[Dict[str, Any]], output_path: Path):
    """GRAPH 3: Findings by severity."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6), gridspec_kw={"width_ratios": [1, 1.2]})

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors = [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_INFO]
    sev_totals = [summary.get("findings_by_severity", {}).get(s, 0) for s in sev_order]
    total_findings = sum(sev_totals)

    # Left: Total findings aggregated across all 100 APKs
    bars1 = ax1.bar(sev_order, sev_totals, color=sev_colors, edgecolor="#334155", linewidth=0.8, width=0.55)
    ax1.set_title(f"Total Findings by Severity Band (Sum = {total_findings:,})", pad=12)
    ax1.set_ylabel("Count of Distinct Findings (Not APKs)", fontweight="bold")
    ax1.set_ylim(0, max(sev_totals) * 1.15 if max(sev_totals) > 0 else 10)

    for bar, val in zip(bars1, sev_totals):
        pct = (val / total_findings * 100) if total_findings > 0 else 0
        ax1.annotate(
            f"{val:,}\n({pct:.1f}%)",
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            xytext=(0, 4),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=8.5,
        )

    # Right: Average findings per APK by stratum or top finding counts
    sorted_recs = sorted(records, key=lambda r: r.get("findings_total", 0), reverse=True)
    findings_per_apk = [r.get("findings_total", 0) for r in sorted_recs]
    bins = [0, 5, 10, 15, 20, 25, 30, 40]
    counts, edges = np.histogram(findings_per_apk, bins=bins)
    bin_labels = [f"{bins[i]}-{bins[i+1]-1}" for i in range(len(bins)-1)]

    bars2 = ax2.bar(bin_labels, counts, color="#0284c7", edgecolor="#334155", linewidth=0.8, width=0.6)
    ax2.set_title("Findings Density Distribution across Evaluated APKs", pad=12)
    ax2.set_xlabel("Number of Security Findings per APK", fontweight="bold")
    ax2.set_ylabel("Count of APK Samples (Denominator N=100)", fontweight="bold")

    for bar, val in zip(bars2, counts):
        if val > 0:
            ax2.annotate(
                f"{val}",
                xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

    plt.suptitle("Graph 3: Distribution and Density of Security Findings by Severity Band",
                 fontsize=13, fontweight="bold", y=0.98)
    fig.text(0.5, 0.92, "Note: Left chart represents total deduplicated findings; right chart represents findings density per APK",
             ha="center", fontsize=8.5, style="italic", color="#475569")

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_04_module_execution_coverage(summary: Dict[str, Any], output_path: Path):
    """GRAPH 4: Module execution coverage."""
    fig, ax = plt.subplots(figsize=(11, 5.5))

    counts = summary.get("sample_counts", {})
    total = counts.get("selected_samples", 100)

    modules = [
        "Static DEX & Manifest",
        "Permission Analysis",
        "Dynamic Sandbox (Stage 2B)",
        "Network Telemetry (Stage 2C)",
        "BLE Telemetry",
    ]

    completed = [
        counts.get("static_completed", 0),
        counts.get("permission_completed", 0),
        counts.get("dynamic_completed", 0),
        0,
        0,
    ]
    failed_unavail = [
        0,
        0,
        counts.get("dynamic_failed_or_unavailable", 0),
        0,
        0,
    ]
    untested_unreq = [
        total - completed[0] - failed_unavail[0],
        total - completed[1] - failed_unavail[1],
        total - completed[2] - failed_unavail[2],
        total,
        total,
    ]

    y = np.arange(len(modules))
    height = 0.55

    p1 = ax.barh(y, completed, height, label="Completed / Successful", color=COLOR_LOW, edgecolor="#334155")
    p2 = ax.barh(y, failed_unavail, height, left=completed, label="Incompatible / Blocked / Failed", color=COLOR_CRITICAL, edgecolor="#334155")
    p3 = ax.barh(y, untested_unreq, height, left=np.array(completed) + np.array(failed_unavail),
                 label="Not Requested / Not Implemented", color=COLOR_MUTED, edgecolor="#334155", alpha=0.6)

    ax.set_xlabel("Number of Evaluated Samples (Explicit Denominator N = 100)", fontweight="bold")
    ax.set_title("Graph 4: Pipeline Module Execution Coverage and Environmental Readiness", pad=15)
    plt.suptitle("Auditing Pipeline Completeness, Dynamic Compatibility Isolation, and Architectural Support",
                 fontsize=9.5, style="italic", y=0.92, color="#475569")

    ax.set_yticks(y)
    ax.set_yticklabels(modules, fontweight="medium")
    ax.set_xlim(0, 110)
    ax.legend(loc="lower right", framealpha=0.9, fontsize=8.5)

    for i in range(len(modules)):
        c_val = completed[i]
        f_val = failed_unavail[i]
        label_parts = []
        if c_val > 0:
            label_parts.append(f"{c_val} Completed")
        if f_val > 0:
            label_parts.append(f"{f_val} Blocked/Failed")
        txt = " / ".join(label_parts) if label_parts else "0 (N/A)"
        ax.text(total + 1.5, i, txt, va="center", fontweight="bold", fontsize=8.5, color=COLOR_DARK)

    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_05_dynamic_execution_outcomes(summary: Dict[str, Any], output_path: Path):
    """GRAPH 5: Dynamic execution outcomes breakdown."""
    fig, ax = plt.subplots(figsize=(11, 6))

    outcomes = summary.get("sample_counts", {}).get("dynamic_outcomes", {})
    categories = [
        ("OBSERVED", "Successful Observation (Stage 2B Completed)", COLOR_LOW),
        ("BLOCKED_ABI", "ABI Incompatible (Isolated before install)", "#d97706"),
        ("NOT_TESTED_NO_LAUNCHER", "No Launchable Activity Declared", "#0284c7"),
        ("FAILED_INSTALL", "Installation Failure", COLOR_HIGH),
        ("FAILED_LAUNCH", "Activity Launch Failure", COLOR_CRITICAL),
        ("FAILED_OBSERVATION", "Runtime Observation / Boot Failure", "#7c3aed"),
        ("UNAVAILABLE", "Unavailable / Duplicate AVD State", COLOR_MUTED),
    ]

    labels = [c[1] for c in categories]
    counts = [outcomes.get(c[0], 0) for c in categories]
    colors = [c[2] for c in categories]
    total = sum(counts) if sum(counts) > 0 else 100

    y = np.arange(len(categories))
    bars = ax.barh(y, counts, color=colors, edgecolor="#334155", linewidth=0.8, height=0.6)

    ax.set_xlabel("Number of Samples (Denominator N = 100)", fontweight="bold")
    ax.set_title("Graph 5: Authoritative Dynamic Sandbox Execution Outcomes (N = 100)", pad=15)
    plt.suptitle("Distinguishing Successful Telemetry Observations, Pre-Install ABI Isolation, and Execution Failures",
                 fontsize=9.5, style="italic", y=0.92, color="#475569")

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontweight="medium")
    ax.set_xlim(0, max(counts) * 1.25 if max(counts) > 0 else 50)

    for bar, val in zip(bars, counts):
        pct = (val / total) * 100
        ax.text(
            val + 0.8,
            bar.get_y() + bar.get_height() / 2,
            f"{val} ({pct:.1f}%)",
            va="center",
            fontweight="bold",
            fontsize=8.5,
            color=COLOR_DARK,
        )

    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_06_sensitive_permission_distribution(records: List[Dict[str, Any]], output_path: Path):
    """GRAPH 6: Sensitive permission distribution."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), gridspec_kw={"width_ratios": [1, 1.2]})

    # Left: Histogram of declared permission counts
    perm_counts = [r.get("permissions", {}).get("declared_count", 0) for r in records]
    bins = [0, 5, 10, 15, 20, 30, 50, 100]
    counts, edges = np.histogram(perm_counts, bins=bins)
    bin_labels = [f"{bins[i]}-{bins[i+1]-1}" for i in range(len(bins)-1)]

    bars1 = ax1.bar(bin_labels, counts, color=COLOR_ACCENT, edgecolor="#334155", linewidth=0.8, width=0.6)
    ax1.set_title("Declared Permission Volume Distribution", pad=12)
    ax1.set_xlabel("Declared Permissions Count Range", fontweight="bold")
    ax1.set_ylabel("Number of APK Samples (N=100)", fontweight="bold")
    ax1.set_ylim(0, max(counts) * 1.15 if max(counts) > 0 else 10)

    for bar, val in zip(bars1, counts):
        if val > 0:
            ax1.annotate(
                f"{val}",
                xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

    # Right: Prevalence of sensitive surveillance permission categories
    categories = {
        "Internet / Network": lambda perms: any("INTERNET" in p for p in perms),
        "Telephony / SMS": lambda perms: any("SMS" in p or "CALL" in p or "PHONE_STATE" in p for p in perms),
        "Location (Fine/Coarse)": lambda perms: any("LOCATION" in p for p in perms),
        "Camera": lambda perms: any("CAMERA" in p for p in perms),
        "Audio Recording": lambda perms: any("RECORD_AUDIO" in p for p in perms),
        "Overlay (Draw Over)": lambda perms: any("SYSTEM_ALERT_WINDOW" in p for p in perms),
        "Contacts / Storage": lambda perms: any("CONTACTS" in p or "STORAGE" in p for p in perms),
        "Boot Persistence": lambda perms: any("RECEIVE_BOOT_COMPLETED" in p for p in perms),
    }

    cat_labels = list(categories.keys())
    cat_counts = []
    for label, fn in categories.items():
        cnt = sum(1 for r in records if fn(r.get("permissions", {}).get("declared_permissions", [])))
        cat_counts.append(cnt)

    y_pos = np.arange(len(cat_labels))
    bars2 = ax2.barh(y_pos, cat_counts, color="#0284c7", edgecolor="#334155", linewidth=0.8, height=0.6)
    ax2.set_title("Surveillance Permission Category Prevalence", pad=12)
    ax2.set_xlabel("Number of APKs Declaring Category (Denominator N = 100)", fontweight="bold")
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(cat_labels, fontweight="medium")
    ax2.set_xlim(0, 110)

    for bar, val in zip(bars2, cat_counts):
        pct = (val / len(records)) * 100
        ax2.text(val + 1.5, bar.get_y() + bar.get_height() / 2, f"{val} ({pct:.0f}%)",
                 va="center", fontweight="bold", fontsize=8.5, color=COLOR_DARK)

    plt.suptitle("Graph 6: Android Permission Distribution and Surveillance Vector Footprint",
                 fontsize=13, fontweight="bold", y=0.98)
    fig.text(0.5, 0.92, "Parsed Directly from Authentic AndroidManifest.xml Declarations (Declaration != Runtime Behavior)",
             ha="center", fontsize=8.5, style="italic", color="#475569")

    fig.tight_layout(rect=[0, 0, 1, 0.90])
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_07_static_vs_dynamic_comparison(records: List[Dict[str, Any]], output_path: Path):
    """GRAPH 7: Static vs Dynamic comparison for samples with genuinely usable dynamic observations."""
    fig, ax = plt.subplots(figsize=(13, 6))

    # Filter to genuinely completed dynamic observations
    completed_records = [
        r for r in records
        if r.get("module_status", {}).get("dynamic") == "COMPLETED"
        and r.get("module_scores", {}).get("dynamic") is not None
    ]
    completed_records.sort(key=lambda r: r.get("overall_score") or 0.0, reverse=True)

    n_dyn = len(completed_records)
    labels = [
        f"#{r.get('sample_index', i+1)}\n{r.get('package_name', r['filename'])[:12]}\n({r['sha256'][:6]})"
        for i, r in enumerate(completed_records)
    ]
    x = np.arange(n_dyn)
    width = 0.36

    static_scores = [r.get("module_scores", {}).get("static") or 0.0 for r in completed_records]
    dynamic_scores = [r.get("module_scores", {}).get("dynamic") or 0.0 for r in completed_records]

    rects1 = ax.bar(x - width/2, static_scores, width, label="Static Score (Bytecode & Manifest)", color=COLOR_ACCENT, edgecolor="#334155")
    rects2 = ax.bar(x + width/2, dynamic_scores, width, label="Dynamic Score (Runtime Telemetry)", color=COLOR_HIGH, edgecolor="#334155")

    ax.set_ylabel("Component Risk Score (0–100 Bounded Scale)", fontweight="bold")
    ax.set_xlabel(f"Evaluated Samples with Completed Dynamic Observations (N = {n_dyn})", fontweight="bold")
    ax.set_title(f"Graph 7: Static Inspection vs. Dynamic Sandbox Scores (N = {n_dyn} Completed Observations)", pad=15)
    plt.suptitle("Descriptive Comparison between Static Capability Indicators and Demonstrated 15s Runtime Telemetry (Not Accuracy Proof)",
                 fontsize=9.5, style="italic", y=0.92, color="#475569")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7.5)
    ax.set_ylim(0, 108)
    ax.legend(loc="upper right", framealpha=0.9, fontsize=8.5)

    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_08_risk_score_distribution(records: List[Dict[str, Any]], output_path: Path):
    """GRAPH 8: Risk score distribution histogram across readable bins."""
    fig, ax = plt.subplots(figsize=(10, 5.5))

    scores = [r.get("overall_score") or 0.0 for r in records if r.get("overall_score") is not None]
    bins = np.arange(0, 105, 10)  # 0-10, 10-20, ..., 90-100
    counts, edges = np.histogram(scores, bins=bins)
    bin_labels = [f"{int(edges[i])}–{int(edges[i+1])}" for i in range(len(edges)-1)]

    # Color bins according to severity thresholds
    colors = []
    for edge in edges[:-1]:
        if edge >= 70:
            colors.append(COLOR_CRITICAL)
        elif edge >= 50:
            colors.append(COLOR_HIGH)
        elif edge >= 20:
            colors.append(COLOR_MEDIUM)
        else:
            colors.append(COLOR_LOW)

    x = np.arange(len(bin_labels))
    bars = ax.bar(x, counts, color=colors, edgecolor="#334155", linewidth=0.8, width=0.65)

    ax.set_xlabel("Overall Risk Score Interval (0–100 Bounded Scale)", fontweight="bold")
    ax.set_ylabel("Number of Evaluated Samples (N = 100)", fontweight="bold")
    ax.set_title("Graph 8: Bounded Aggregate Risk Score Distribution (N = 100)", pad=15)
    plt.suptitle("Histogram of Peak-and-Mean Calculated Risk Scores across 10-Point Score Intervals",
                 fontsize=9.5, style="italic", y=0.92, color="#475569")

    ax.set_xticks(x)
    ax.set_xticklabels(bin_labels, fontweight="medium")
    ax.set_ylim(0, max(counts) * 1.2 if max(counts) > 0 else 20)

    for bar, val in zip(bars, counts):
        if val > 0:
            pct = (val / len(scores)) * 100
            ax.annotate(
                f"{val}\n({pct:.0f}%)",
                xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontweight="bold",
                fontsize=8.5,
            )

    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def main():
    parser = argparse.ArgumentParser(description="Generate 100-Sample Evaluation Figures")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path("/home/j3st3r/Desktop/SpyAware-Report-Preparation/SpyAware-CIC-Evaluation-100/results"),
        help="Path to results directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/home/j3st3r/Desktop/SpyAware-Report-Preparation/SpyAware-CIC-Evaluation-100/graphs"),
        help="Path to graphs output directory",
    )

    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    summary_file = args.results_dir / "evaluation_summary.json"
    per_apk_file = args.results_dir / "per_apk_results.json"

    if not summary_file.exists() or not per_apk_file.exists():
        logger.error("Results files not found in %s. Run evaluation first.", args.results_dir)
        return

    with open(summary_file, "r", encoding="utf-8") as f:
        summary = json.load(f)
    with open(per_apk_file, "r", encoding="utf-8") as f:
        records = json.load(f)

    setup_plot_style()

    logger.info("Generating publication-grade figures for 100-sample evaluation...")
    graph_01_risk_score_by_apk(records, args.output_dir / "01_risk_score_by_apk.png")
    graph_02_risk_classification_distribution(summary, args.output_dir / "02_risk_classification_distribution.png")
    graph_03_findings_by_severity(summary, records, args.output_dir / "03_findings_by_severity.png")
    graph_04_module_execution_coverage(summary, args.output_dir / "04_module_execution_coverage.png")
    graph_05_dynamic_execution_outcomes(summary, args.output_dir / "05_dynamic_execution_outcomes.png")
    graph_06_sensitive_permission_distribution(records, args.output_dir / "06_sensitive_permission_distribution.png")
    graph_07_static_vs_dynamic_comparison(records, args.output_dir / "07_static_vs_dynamic_comparison.png")
    graph_08_risk_score_distribution(records, args.output_dir / "08_risk_score_distribution.png")
    logger.info("All 8 figures successfully generated in %s", args.output_dir)


if __name__ == "__main__":
    main()
