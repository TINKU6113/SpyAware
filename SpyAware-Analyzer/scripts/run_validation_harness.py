#!/usr/bin/env python3
"""CLI runner for SpyAware-Analyzer Detection Validation Harness.

Milestone M4: Detection Validation and Analysis Accuracy.
Executes the deterministic validation corpus, evaluates detection accuracy,
verifies secret redaction, prints tabular performance metrics, and exports
reports/validation_results.json.
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzers.validation.harness import ValidationHarness


def main():
    parser = argparse.ArgumentParser(
        description="Run SpyAware-Analyzer Detection Validation Harness."
    )
    parser.add_argument(
        "--corpus-dir",
        type=Path,
        default=None,
        help="Custom directory for synthetic APK validation corpus",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=None,
        help="Custom directory for saving validation results JSON",
    )
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="Force re-generation of all validation APK fixtures",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Only output machine-readable JSON to stdout",
    )

    args = parser.parse_args()

    harness = ValidationHarness(
        corpus_dir=args.corpus_dir,
        reports_dir=args.reports_dir,
    )

    report = harness.run_all(force_rebuild_corpus=args.force_rebuild)

    if args.json_only:
        print(json.dumps(report.model_dump(), indent=2))
        sys.exit(0 if report.failed_cases == 0 else 1)

    # Print human-readable summary
    print("\n" + "=" * 80)
    print(" SPYAWARE ANALYZER — DETECTION VALIDATION HARNESS (MILESTONE M4)")
    print("=" * 80)
    print(f"Timestamp:       {report.timestamp}")
    print(f"Total Cases:     {report.total_cases}")
    print(f"Passed Cases:    {report.passed_cases}")
    print(f"Failed Cases:    {report.failed_cases}")
    print(f"Pipeline Status: {report.pipeline_e2e_status}")
    print(f"Dynamic Status:  {report.dynamic_readiness.status} ({report.dynamic_readiness.reason})")
    print(f"Secret Redaction:{' VERIFIED' if report.redaction_audit_passed else ' FAILED'}")
    print("-" * 80)

    print(f"{'CASE ID':<26} {'GROUND TRUTH':<14} {'PREDICTED RISK':<16} {'MATCHED RULES':<6} {'STATUS'}")
    print("-" * 80)
    for cr in report.case_results:
        risk_str = f"{cr.predicted_risk_level or 'N/A'} ({cr.predicted_risk_score if cr.predicted_risk_score is not None else '-'})"
        status_str = "PASS" if cr.passed else "FAIL"
        matched_cnt = f"{len(cr.matched_rules)}/{len(cr.matched_rules) + len(cr.missing_rules)}"
        print(f"{cr.case_id:<26} {cr.ground_truth:<14} {risk_str:<16} {matched_cnt:<6} {status_str}")

    print("-" * 80)
    print(" RULE-LEVEL EVALUATION METRICS:")
    rm = report.rule_level_metrics
    p_str = f"{rm.precision.value:.4f} ({rm.precision.numerator}/{rm.precision.denominator})" if rm.precision.is_defined else f"UNDEFINED ({rm.precision.explanation})"
    r_str = f"{rm.recall.value:.4f} ({rm.recall.numerator}/{rm.recall.denominator})" if rm.recall.is_defined else f"UNDEFINED ({rm.recall.explanation})"
    fpr_str = f"{rm.false_positive_rate.value:.4f} ({rm.false_positive_rate.numerator}/{rm.false_positive_rate.denominator})" if rm.false_positive_rate.is_defined else f"UNDEFINED ({rm.false_positive_rate.explanation})"
    fnr_str = f"{rm.false_negative_rate.value:.4f} ({rm.false_negative_rate.numerator}/{rm.false_negative_rate.denominator})" if rm.false_negative_rate.is_defined else f"UNDEFINED ({rm.false_negative_rate.explanation})"
    acc_str = f"{rm.accuracy.value:.4f} ({rm.accuracy.numerator}/{rm.accuracy.denominator})" if rm.accuracy.is_defined else f"UNDEFINED ({rm.accuracy.explanation})"
    print(f"  TP: {rm.true_positives:<4} FP: {rm.false_positives:<4} TN: {rm.true_negatives:<4} FN: {rm.false_negatives:<4}")
    print(f"  Precision: {p_str}")
    print(f"  Recall:    {r_str}")
    print(f"  FPR:       {fpr_str}")
    print(f"  FNR:       {fnr_str}")
    print(f"  Accuracy:  {acc_str}")

    print("-" * 80)
    print(" SAMPLE-LEVEL CLASSIFICATION METRICS (ELEVATED RISK vs BENIGN):")
    cm = report.classification_metrics
    cp_str = f"{cm.precision.value:.4f} ({cm.precision.numerator}/{cm.precision.denominator})" if cm.precision.is_defined else f"UNDEFINED ({cm.precision.explanation})"
    cr_str = f"{cm.recall.value:.4f} ({cm.recall.numerator}/{cm.recall.denominator})" if cm.recall.is_defined else f"UNDEFINED ({cm.recall.explanation})"
    cfpr_str = f"{cm.false_positive_rate.value:.4f} ({cm.false_positive_rate.numerator}/{cm.false_positive_rate.denominator})" if cm.false_positive_rate.is_defined else f"UNDEFINED ({cm.false_positive_rate.explanation})"
    cfnr_str = f"{cm.false_negative_rate.value:.4f} ({cm.false_negative_rate.numerator}/{cm.false_negative_rate.denominator})" if cm.false_negative_rate.is_defined else f"UNDEFINED ({cm.false_negative_rate.explanation})"
    cacc_str = f"{cm.accuracy.value:.4f} ({cm.accuracy.numerator}/{cm.accuracy.denominator})" if cm.accuracy.is_defined else f"UNDEFINED ({cm.accuracy.explanation})"
    print(f"  TP: {cm.true_positives:<4} FP: {cm.false_positives:<4} TN: {cm.true_negatives:<4} FN: {cm.false_negatives:<4}")
    print(f"  Precision: {cp_str}")
    print(f"  Recall:    {cr_str}")
    print(f"  FPR:       {cfpr_str}")
    print(f"  FNR:       {cfnr_str}")
    print(f"  Accuracy:  {cacc_str}")

    print("=" * 80)
    print(f"Report saved to: {harness.reports_dir / 'validation_results.json'}")
    print("=" * 80 + "\n")

    sys.exit(0 if report.failed_cases == 0 else 1)


if __name__ == "__main__":
    main()
