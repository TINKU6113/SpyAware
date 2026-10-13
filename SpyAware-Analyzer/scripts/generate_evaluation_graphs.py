#!/usr/bin/env python3
"""Professional Evaluation Results Visualization Generator for SpyAware-Analyzer.

Milestone Phase I:
Generates 6 publication-grade, high-resolution (300 DPI) figures using Matplotlib
(strictly without Seaborn) directly from authentic evaluation results:

1. 01_risk_score_by_apk.png: Overall aggregate risk score per evaluated sample with risk levels.
2. 02_findings_by_severity.png: Distribution of findings grouped by severity band (CRITICAL, HIGH, MEDIUM, LOW, INFO).
3. 03_module_execution_coverage.png: Execution completion and failure distribution across analysis modules.
4. 04_permission_distribution.png: Declared Android permission counts and surveillance category footprint.
5. 05_dynamic_telemetry_status.png: Runtime observation states (OBSERVED, NOT_OBSERVED, UNAVAILABLE, NOT_TESTED) across 10 surveillance categories.
6. 06_static_vs_dynamic_coverage.png: Comparative completion rate between static inspection and dynamic sandbox execution.
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
logger = logging.getLogger("graph_generator")

# Professional cybersecurity report color palette
COLOR_CRITICAL = "#dc2626"  # Deep red
COLOR_HIGH = "#ea580c"      # Orange
COLOR_MEDIUM = "#ca8a04"    # Dark goldenrod / Amber
COLOR_LOW = "#16a34a"       # Forest green
COLOR_INFO = "#0284c7"      # Blue / Sky
COLOR_MUTED = "#64748b"     # Slate gray
COLOR_DARK = "#0f172a"      # Navy / Slate dark
COLOR_BG = "#f8fafc"        # Off-white background
COLOR_ACCENT = "#2563eb"    # Royal blue


def setup_plot_style():
    """Sets clean typography and presentation defaults."""
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 10,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "axes.labelsize": 10,
        "axes.labelweight": "medium",
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "figure.titlesize": 14,
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
    """GRAPH 1: RISK SCORE BY APK."""
    fig, ax = plt.subplots(figsize=(12, 6.5))

    sorted_records = sorted(records, key=lambda r: r.get("overall_score") or 0.0, reverse=True)
    labels = [
        f"{r.get('package_name', r['filename'])[:18]}\n({r['sha256'][:8]})"
        for r in sorted_records
    ]
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

    x = np.arange(len(labels))
    bars = ax.bar(x, scores, color=bar_colors, edgecolor="#334155", linewidth=0.8, width=0.65)

    ax.set_ylabel("Overall Risk Score (0–100 Bounded Scale)", fontweight="bold")
    ax.set_xlabel("Analyzed Application Identifier (Package / SHA-256 Prefix)", fontweight="bold")
    ax.set_title("Graph 1: SpyAware Aggregate Risk Score by Evaluated APK Sample", pad=15)
    plt.suptitle("Peak-and-Mean Multi-Module Bounded Risk Calculation across 15 Representative Samples",
                 fontsize=10, style="italic", y=0.92, color="#475569")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8.5)
    ax.set_ylim(0, 105)

    # Threshold horizontal reference bands
    ax.axhline(75, color=COLOR_CRITICAL, linestyle=":", alpha=0.6, label="Critical Threshold (>=75)")
    ax.axhline(50, color=COLOR_HIGH, linestyle=":", alpha=0.6, label="High Threshold (>=50)")
    ax.axhline(25, color=COLOR_MEDIUM, linestyle=":", alpha=0.6, label="Medium Threshold (>=25)")

    # Data value labels on bars
    for bar, score, lvl in zip(bars, scores, levels):
        height = bar.get_height()
        ax.annotate(
            f"{score:.1f}\n[{lvl[:4]}]",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8,
            fontweight="bold",
            color="#1e293b",
        )

    ax.legend(loc="upper right", framealpha=0.9, fontsize=8.5)
    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_02_findings_by_severity(records: List[Dict[str, Any]], summary: Dict[str, Any], output_path: Path):
    """GRAPH 2: FINDINGS BY SEVERITY."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6), gridspec_kw={"width_ratios": [1, 1.4]})

    # Left: Total findings aggregated across all APKs
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors = [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_INFO]
    sev_totals = [summary.get("findings_by_severity", {}).get(s, 0) for s in sev_order]

    bars1 = ax1.bar(sev_order, sev_totals, color=sev_colors, edgecolor="#334155", linewidth=0.8, width=0.55)
    ax1.set_title("Total Findings by Severity Band", pad=12)
    ax1.set_ylabel("Count of Confirmed Findings", fontweight="bold")
    ax1.set_ylim(0, max(sev_totals) * 1.2 if max(sev_totals) > 0 else 10)

    for bar, val in zip(bars1, sev_totals):
        ax1.annotate(
            f"{val}",
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontweight="bold",
            fontsize=9.5,
        )

    # Right: Stacked breakdown per sample
    sorted_recs = sorted(records, key=lambda r: r.get("findings_total", 0), reverse=True)
    labels = [r.get("package_name", r["filename"])[:14] for r in sorted_recs]
    x = np.arange(len(labels))
    bottom = np.zeros(len(labels))

    for s_name, s_color in zip(sev_order, sev_colors):
        counts = [r.get("findings_by_severity", {}).get(s_name, 0) for r in sorted_recs]
        ax2.bar(x, counts, bottom=bottom, label=s_name, color=s_color, edgecolor="#334155", linewidth=0.5, width=0.65)
        bottom += np.array(counts)

    ax2.set_title("Findings Composition per Evaluated Sample", pad=12)
    ax2.set_ylabel("Cumulative Finding Count", fontweight="bold")
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=45, ha="right", fontsize=8.5)
    ax2.legend(loc="upper right", framealpha=0.9, fontsize=8.5)

    plt.suptitle("Graph 2: Distribution and Density of Security Findings by Severity",
                 fontsize=14, fontweight="bold", y=0.98)
    fig.text(0.5, 0.93, "Deduplicated Rule Detections Across Manifest Inspection, DEX Indicators, and Runtime Observations",
             ha="center", fontsize=9.5, style="italic", color="#475569")

    fig.tight_layout(rect=[0, 0, 1, 0.91])
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_03_module_execution_coverage(summary: Dict[str, Any], output_path: Path):
    """GRAPH 3: MODULE EXECUTION COVERAGE."""
    fig, ax = plt.subplots(figsize=(10, 6))

    counts = summary.get("sample_counts", {})
    total = counts.get("selected_samples", 15)

    modules = ["Static DEX & Manifest", "Permission Analysis", "Dynamic Sandbox (Stage 2B)", "Network Telemetry (Stage 2C)", "BLE Telemetry"]
    
    completed = [
        counts.get("static_completed", 0),
        counts.get("permission_completed", 0),
        counts.get("dynamic_completed", 0),
        0,  # Network was not requested in this run profile
        0,  # BLE is coming soon
    ]
    failed = [
        0,
        0,
        counts.get("dynamic_failed_or_unavailable", 0),
        0,
        0,
    ]
    untested_unreq = [
        total - completed[0] - failed[0],
        total - completed[1] - failed[1],
        total - completed[2] - failed[2],
        total,  # 15 not requested
        total,  # 15 not implemented
    ]

    y = np.arange(len(modules))
    height = 0.55

    p1 = ax.barh(y, completed, height, label="Completed / Successful", color=COLOR_LOW, edgecolor="#334155")
    p2 = ax.barh(y, failed, height, left=completed, label="Failed / Incompatible / Unavailable", color=COLOR_CRITICAL, edgecolor="#334155")
    p3 = ax.barh(y, untested_unreq, height, left=np.array(completed) + np.array(failed),
                 label="Not Requested / Not Implemented", color=COLOR_MUTED, edgecolor="#334155", alpha=0.6)

    ax.set_xlabel("Number of Evaluated Samples (Total = 15)", fontweight="bold")
    ax.set_title("Graph 3: Module Execution Coverage and Environmental Readiness", pad=15)
    plt.suptitle("Auditing Pipeline Pipeline Completeness, ABI Compatibility Rejections, and Module Execution Status",
                 fontsize=9.5, style="italic", y=0.92, color="#475569")

    ax.set_yticks(y)
    ax.set_yticklabels(modules, fontweight="medium")
    ax.set_xlim(0, 16)
    ax.legend(loc="lower right", framealpha=0.9, fontsize=9)

    for i in range(len(modules)):
        c_val = completed[i]
        f_val = failed[i]
        label_parts = []
        if c_val > 0:
            label_parts.append(f"{c_val} OK")
        if f_val > 0:
            label_parts.append(f"{f_val} Blocked")
        txt = " / ".join(label_parts) if label_parts else "0 (N/A)"
        ax.text(total + 0.3, i, txt, va="center", fontweight="bold", fontsize=9, color=COLOR_DARK)

    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_04_permission_distribution(records: List[Dict[str, Any]], output_path: Path):
    """GRAPH 4: PERMISSION DISTRIBUTION."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6), gridspec_kw={"width_ratios": [1, 1.2]})

    # Left: Histogram of declared permission counts
    perm_counts = [r.get("permissions", {}).get("declared_count", 0) for r in records]
    bins = [0, 5, 10, 15, 20, 30, 50]
    counts, edges = np.histogram(perm_counts, bins=bins)
    bin_labels = [f"{bins[i]}-{bins[i+1]}" for i in range(len(bins)-1)]

    bars1 = ax1.bar(bin_labels, counts, color=COLOR_ACCENT, edgecolor="#334155", linewidth=0.8, width=0.6)
    ax1.set_title("Declared Permission Volume Distribution", pad=12)
    ax1.set_xlabel("Declared Permissions Range", fontweight="bold")
    ax1.set_ylabel("Number of APK Samples", fontweight="bold")
    ax1.set_ylim(0, max(counts) + 2)

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

    # Right: Prevalance of sensitive surveillance permission categories
    categories = {
        "Internet / Network": lambda perms: any("INTERNET" in p for p in perms),
        "Telephony / SMS": lambda perms: any("SMS" in p or "CALL" in p or "PHONE_STATE" in p for p in perms),
        "Location (Fine/Coarse)": lambda perms: any("LOCATION" in p for p in perms),
        "Camera": lambda perms: any("CAMERA" in p for p in perms),
        "Audio Recording": lambda perms: any("RECORD_AUDIO" in p for p in perms),
        "Overlay (Draw Over)": lambda perms: any("SYSTEM_ALERT_WINDOW" in p for p in perms),
        "Contacts / Storage": lambda perms: any("CONTACTS" in p or "STORAGE" in p for p in perms),
    }

    cat_labels = list(categories.keys())
    cat_counts = []
    for label, fn in categories.items():
        cnt = sum(1 for r in records if fn(r.get("permissions", {}).get("declared_permissions", [])))
        cat_counts.append(cnt)

    y_pos = np.arange(len(cat_labels))
    bars2 = ax2.barh(y_pos, cat_counts, color="#0284c7", edgecolor="#334155", linewidth=0.8, height=0.6)
    ax2.set_title("Surveillance Permission Category Prevalence", pad=12)
    ax2.set_xlabel("Number of APKs Declaring Category (Denominator = 15)", fontweight="bold")
    ax2.set_yticks(y_pos)
    ax2.set_yticklabels(cat_labels, fontweight="medium")
    ax2.set_xlim(0, 16)

    for bar, val in zip(bars2, cat_counts):
        pct = (val / len(records)) * 100
        ax2.text(val + 0.3, bar.get_y() + bar.get_height()/2, f"{val} ({pct:.0f}%)",
                 va="center", fontweight="bold", fontsize=8.5, color=COLOR_DARK)

    plt.suptitle("Graph 4: Android Permission Distribution and Surveillance Vector Footprint",
                 fontsize=14, fontweight="bold", y=0.98)
    fig.text(0.5, 0.93, "Parsed Directly from Authentic AndroidManifest.xml Declarations (Note: Declaration != Runtime Use)",
             ha="center", fontsize=9.5, style="italic", color="#475569")

    fig.tight_layout(rect=[0, 0, 1, 0.91])
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_05_dynamic_telemetry_status(summary: Dict[str, Any], output_path: Path):
    """GRAPH 5: DYNAMIC TELEMETRY STATUS."""
    fig, ax = plt.subplots(figsize=(12, 7))

    tele_data = summary.get("runtime_telemetry_by_category", {})
    cats_order = [
        "CAMERA", "MICROPHONE", "LOCATION", "SMS", "CALL",
        "ACCESSIBILITY", "OVERLAY", "CLIPBOARD", "PERSISTENCE", "NETWORK"
    ]
    cat_display = [
        "Camera", "Microphone", "Geolocation", "SMS Intercept", "Call Activity",
        "Accessibility", "Overlay Window", "Clipboard", "Persistence", "Socket Network"
    ]

    observed = [tele_data.get(c, {}).get("OBSERVED", 0) for c in cats_order]
    not_observed = [tele_data.get(c, {}).get("NOT_OBSERVED", 0) for c in cats_order]
    unavailable = [tele_data.get(c, {}).get("UNAVAILABLE", 0) for c in cats_order]
    not_tested = [tele_data.get(c, {}).get("NOT_TESTED", 0) for c in cats_order]

    total_samples = summary.get("sample_counts", {}).get("selected_samples", 15)
    y = np.arange(len(cats_order))
    height = 0.6

    p_obs = ax.barh(y, observed, height, label="OBSERVED (Runtime Activity Detected)", color=COLOR_CRITICAL, edgecolor="#334155")
    p_not_obs = ax.barh(y, not_observed, height, left=observed,
                        label="NOT_OBSERVED (Tested, Dormant / Inactive)", color=COLOR_LOW, edgecolor="#334155")
    p_unavail = ax.barh(y, unavailable, height, left=np.array(observed) + np.array(not_observed),
                        label="UNAVAILABLE (Telemetry Sensor Error)", color=COLOR_HIGH, edgecolor="#334155")
    p_not_test = ax.barh(y, not_tested, height, left=np.array(observed) + np.array(not_observed) + np.array(unavailable),
                         label="NOT_TESTED (Execution Blocked / Incompatible)", color=COLOR_MUTED, edgecolor="#334155", alpha=0.5)

    ax.set_xlabel("Number of Samples (Explicit Denominator N = 15)", fontweight="bold")
    ax.set_title("Graph 5: Runtime Telemetry Observation Across 10 Canonical Surveillance Categories", pad=15)
    plt.suptitle("Authoritative Runtime Statuses Captured via Android Logcat, Dumpsys, and Kernel Sockets (Standard 15s Window)",
                 fontsize=9.5, style="italic", y=0.92, color="#475569")

    ax.set_yticks(y)
    ax.set_yticklabels(cat_display, fontweight="medium")
    ax.set_xlim(0, 16)
    ax.legend(loc="lower right", framealpha=0.95, fontsize=8.5)

    # Label counts
    for i in range(len(cats_order)):
        obs = observed[i]
        n_obs = not_observed[i]
        nt = not_tested[i]
        ax.text(total_samples + 0.3, i, f"{obs} Obs / {n_obs} Dorm / {nt} Unexecuted",
                va="center", fontsize=8, fontweight="bold", color=COLOR_DARK)

    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def graph_06_static_vs_dynamic_coverage(records: List[Dict[str, Any]], output_path: Path):
    """GRAPH 6: STATIC VS DYNAMIC COVERAGE."""
    fig, ax = plt.subplots(figsize=(11, 6))

    sorted_records = sorted(records, key=lambda r: (r.get("module_status", {}).get("dynamic") == "COMPLETED", r.get("overall_score") or 0.0), reverse=True)
    labels = [f"{r.get('package_name', r['filename'])[:16]}\n({r['sha256'][:8]})" for r in sorted_records]
    x = np.arange(len(labels))
    width = 0.38

    static_scores = [r.get("module_scores", {}).get("static") or 0.0 for r in sorted_records]
    dynamic_scores = [r.get("module_scores", {}).get("dynamic") if r.get("module_status", {}).get("dynamic") == "COMPLETED" else 0.0 for r in sorted_records]
    dynamic_statuses = [r.get("module_status", {}).get("dynamic", "NOT_TESTED") for r in sorted_records]

    rects1 = ax.bar(x - width/2, static_scores, width, label="Static Score (Bytecode & Manifest)", color=COLOR_ACCENT, edgecolor="#334155")
    rects2 = ax.bar(x + width/2, dynamic_scores, width, label="Dynamic Score (Runtime Telemetry)", color=COLOR_HIGH, edgecolor="#334155")

    ax.set_ylabel("Component Risk Score (0–100 Scale)", fontweight="bold")
    ax.set_title("Graph 6: Static Inspection vs. Dynamic Sandbox Execution Comparison", pad=15)
    plt.suptitle("Evaluating Static Capability Discovery Against Observable Runtime Behavior and Sandbox Compatibility",
                 fontsize=9.5, style="italic", y=0.92, color="#475569")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8.5)
    ax.set_ylim(0, 105)
    ax.legend(loc="upper right", framealpha=0.9, fontsize=9)

    # Annotate dynamic status tags for blocked/failed ones
    for idx, (rect, status) in enumerate(zip(rects2, dynamic_statuses)):
        if status != "COMPLETED":
            ax.annotate(
                f"[{status[:8]}]",
                xy=(rect.get_x() + rect.get_width() / 2, 2),
                xytext=(0, 4),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=7.5,
                rotation=90,
                color=COLOR_CRITICAL,
                fontweight="bold",
            )

    fig.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logger.info("Saved %s", output_path.name)


def main():
    parser = argparse.ArgumentParser(description="Generate Evaluation Figures")
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=Path("/home/j3st3r/Desktop/SpyAware-Report-Preparation/SpyAware-CIC-Evaluation/results"),
        help="Path to results directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/home/j3st3r/Desktop/SpyAware-Report-Preparation/SpyAware-CIC-Evaluation/graphs"),
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

    logger.info("Generating publication-grade figures...")
    graph_01_risk_score_by_apk(records, args.output_dir / "01_risk_score_by_apk.png")
    graph_02_findings_by_severity(records, summary, args.output_dir / "02_findings_by_severity.png")
    graph_03_module_execution_coverage(summary, args.output_dir / "03_module_execution_coverage.png")
    graph_04_permission_distribution(records, args.output_dir / "04_permission_distribution.png")
    graph_05_dynamic_telemetry_status(summary, args.output_dir / "05_dynamic_telemetry_status.png")
    graph_06_static_vs_dynamic_coverage(records, args.output_dir / "06_static_vs_dynamic_coverage.png")
    logger.info("All 6 figures successfully generated in %s", args.output_dir)


if __name__ == "__main__":
    main()
