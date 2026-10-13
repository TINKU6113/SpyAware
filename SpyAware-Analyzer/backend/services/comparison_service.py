"""Historical Analysis Comparison Service for SpyAware-Analyzer.

Compares two RiskReports with:
- Stable finding keys based on rule_id, category, and component location.
- Categorization of ADDED, REMOVED, MODIFIED, and UNCHANGED findings.
- Comprehensive delta of overall score and module scores.
- Coverage delta: DEX count, permission count, exported components, and dynamic sandbox status.
- Package identity integrity guards: detects exact duplicates, version updates,
  certificate changes, SDK downgrades, and flags unrelated application comparisons.
"""

from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional, Set, Tuple

from backend.models.analysis import Finding, RiskReport, Severity
from backend.models.comparison import (
    AnalysisComparisonReport,
    AnalysisRelationship,
    CoverageDiff,
    FindingDiff,
    FindingDiffStatus,
    ModuleScoreDiff,
    PackageIdentityDiff,
)

logger = logging.getLogger(__name__)


def get_stable_finding_key(finding: Finding) -> str:
    """Computes a stable, normalized identifier for a finding across analyses."""
    if finding.rule_id:
        key = finding.rule_id.strip()
    else:
        norm_title = "_".join(finding.title.strip().upper().split())
        key = f"{finding.category}:{norm_title}"

    if finding.location:
        loc_norm = finding.location.strip().lower()
        key = f"{key}@{loc_norm}"

    return key


class ComparisonService:
    """Performs semantic comparison between two analysis reports."""

    def compare_analyses(
        self,
        base_report: RiskReport,
        target_report: RiskReport,
    ) -> AnalysisComparisonReport:
        """Compares baseline report with target report and generates a structured comparison."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Package Identity & Relationship Diff
        package_identity = self._compare_package_identity(base_report, target_report)
        is_unrelated = package_identity.relationship == AnalysisRelationship.UNRELATED_APKS

        # 2. Risk Score Deltas
        overall_base = round(float(base_report.overall_score), 2)
        overall_target = round(float(target_report.overall_score), 2)
        overall_delta = round(overall_target - overall_base, 2)

        # 3. Module Score Deltas
        module_diffs = self._compare_module_scores(base_report, target_report)

        # 4. Findings Diff
        added, removed, modified, unchanged = self._compare_findings(
            base_report.findings, target_report.findings
        )
        findings_summary = {
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
            "unchanged": len(unchanged),
            "total_base": len(base_report.findings),
            "total_target": len(target_report.findings),
        }

        # 5. Coverage Delta
        coverage_diff = self._compare_coverage(base_report, target_report)

        # 6. Summary Narrative
        summary = self._generate_summary_narrative(
            package_identity=package_identity,
            overall_delta=overall_delta,
            findings_summary=findings_summary,
            base_report=base_report,
            target_report=target_report,
        )

        return AnalysisComparisonReport(
            base_analysis_id=base_report.analysis_id,
            target_analysis_id=target_report.analysis_id,
            base_apk_filename=base_report.apk_filename,
            target_apk_filename=target_report.apk_filename,
            timestamp_comparison=now_iso,
            package_identity=package_identity,
            overall_score_base=overall_base,
            overall_score_target=overall_target,
            overall_score_delta=overall_delta,
            risk_level_base=base_report.risk_level,
            risk_level_target=target_report.risk_level,
            analysis_status_base=base_report.analysis_status,
            analysis_status_target=target_report.analysis_status,
            module_diffs=module_diffs,
            findings_summary=findings_summary,
            added_findings=added,
            removed_findings=removed,
            modified_findings=modified,
            unchanged_findings=unchanged,
            coverage_diff=coverage_diff,
            is_unrelated_warning=is_unrelated,
            summary=summary,
        )

    def _compare_package_identity(
        self, base: RiskReport, target: RiskReport
    ) -> PackageIdentityDiff:
        """Inspects package names, versions, hashes, signing certificates, and SDK levels."""
        warnings: List[str] = []

        base_pkg = (
            base.static_details.package_name
            if base.static_details and base.static_details.package_name
            else None
        )
        target_pkg = (
            target.static_details.package_name
            if target.static_details and target.static_details.package_name
            else None
        )

        base_ver = (
            base.static_details.version_name
            if base.static_details and base.static_details.version_name
            else None
        )
        target_ver = (
            target.static_details.version_name
            if target.static_details and target.static_details.version_name
            else None
        )

        base_hash = base.sha256 or (
            base.static_details.sha256 if base.static_details else None
        )
        target_hash = target.sha256 or (
            target.static_details.sha256 if target.static_details else None
        )

        base_min = (
            base.static_details.min_sdk
            if base.static_details and base.static_details.min_sdk
            else None
        )
        target_min = (
            target.static_details.min_sdk
            if target.static_details and target.static_details.min_sdk
            else None
        )

        base_target_sdk = (
            base.static_details.target_sdk
            if base.static_details and base.static_details.target_sdk
            else None
        )
        target_target_sdk = (
            target.static_details.target_sdk
            if target.static_details and target.static_details.target_sdk
            else None
        )

        base_cert = (
            base.certificate_info.sha256_fingerprint
            if base.certificate_info and base.certificate_info.sha256_fingerprint
            else None
        )
        target_cert = (
            target.certificate_info.sha256_fingerprint
            if target.certificate_info and target.certificate_info.sha256_fingerprint
            else None
        )

        is_hash_identical = bool(base_hash and target_hash and base_hash == target_hash)
        is_package_changed = bool(base_pkg and target_pkg and base_pkg != target_pkg)
        is_version_changed = bool(base_ver and target_ver and base_ver != target_ver)
        is_cert_changed = bool(base_cert and target_cert and base_cert != target_cert)

        # Classify relationship
        if base_pkg and target_pkg and base_pkg != target_pkg:
            relationship = AnalysisRelationship.UNRELATED_APKS
        elif is_hash_identical:
            relationship = AnalysisRelationship.SAME_APK_EXACT
        elif base_pkg and target_pkg and base_pkg == target_pkg:
            if is_version_changed:
                relationship = AnalysisRelationship.SAME_PACKAGE_VERSION_UPDATE
            else:
                relationship = AnalysisRelationship.SAME_PACKAGE_SAME_VERSION
        else:
            relationship = AnalysisRelationship.UNKNOWN

        # Build warnings
        if relationship == AnalysisRelationship.UNRELATED_APKS:
            warnings.append(
                f"UNRELATED APPLICATION WARNING: Comparing two completely different packages "
                f"('{base_pkg}' vs '{target_pkg}'). Risk and finding differences reflect "
                f"different applications, not version changes."
            )

        if is_cert_changed:
            warnings.append(
                f"SIGNING CERTIFICATE MISMATCH: The signing certificate changed from base "
                f"({base_cert[:16]}...) to target ({target_cert[:16]}...). "
                f"This may indicate app repackaging, key rotation, or unauthorized modification."
            )

        if base_target_sdk and target_target_sdk:
            try:
                b_sdk = int(base_target_sdk)
                t_sdk = int(target_target_sdk)
                if t_sdk < b_sdk:
                    warnings.append(
                        f"TARGET SDK DOWNGRADE DETECTED: Target SDK downgraded from {b_sdk} to {t_sdk}. "
                        f"Downgrading targetSdk can be an evasion technique to bypass newer Android runtime permission restrictions."
                    )
            except (ValueError, TypeError):
                pass

        return PackageIdentityDiff(
            relationship=relationship,
            base_package_name=base_pkg,
            target_package_name=target_pkg,
            is_package_changed=is_package_changed,
            base_version=base_ver,
            target_version=target_ver,
            is_version_changed=is_version_changed,
            base_sha256=base_hash,
            target_sha256=target_hash,
            is_hash_identical=is_hash_identical,
            base_min_sdk=base_min,
            target_min_sdk=target_min,
            base_target_sdk=base_target_sdk,
            target_target_sdk=target_target_sdk,
            base_cert_sha256=base_cert,
            target_cert_sha256=target_cert,
            is_cert_changed=is_cert_changed,
            warnings=warnings,
        )

    def _compare_module_scores(
        self, base: RiskReport, target: RiskReport
    ) -> Dict[str, ModuleScoreDiff]:
        """Calculates delta across individual analysis modules."""
        modules = ["static", "permissions", "dynamic", "network", "ble"]
        diffs: Dict[str, ModuleScoreDiff] = {}

        for mod in modules:
            b_score = getattr(base.module_scores, mod, None)
            t_score = getattr(target.module_scores, mod, None)

            b_status = base.module_status.get(mod)
            t_status = target.module_status.get(mod)

            delta = None
            if b_score is not None and t_score is not None:
                delta = round(float(t_score) - float(b_score), 2)

            status_changed = bool(b_status != t_status)

            diffs[mod] = ModuleScoreDiff(
                module_name=mod,
                base_score=round(float(b_score), 2) if b_score is not None else None,
                target_score=round(float(t_score), 2) if t_score is not None else None,
                score_delta=delta,
                base_status=b_status,
                target_status=t_status,
                status_changed=status_changed,
            )

        return diffs

    def _compare_findings(
        self, base_findings: List[Finding], target_findings: List[Finding]
    ) -> Tuple[List[FindingDiff], List[FindingDiff], List[FindingDiff], List[FindingDiff]]:
        """Maps findings by stable canonical key to isolate ADDED, REMOVED, MODIFIED, and UNCHANGED."""
        base_map: Dict[str, Finding] = {}
        for f in base_findings:
            key = get_stable_finding_key(f)
            base_map[key] = f

        target_map: Dict[str, Finding] = {}
        for f in target_findings:
            key = get_stable_finding_key(f)
            target_map[key] = f

        all_keys: Set[str] = set(base_map.keys()).union(set(target_map.keys()))

        added: List[FindingDiff] = []
        removed: List[FindingDiff] = []
        modified: List[FindingDiff] = []
        unchanged: List[FindingDiff] = []

        for key in sorted(all_keys):
            b_find = base_map.get(key)
            t_find = target_map.get(key)

            if b_find is None and t_find is not None:
                added.append(
                    FindingDiff(
                        finding_key=key,
                        status=FindingDiffStatus.ADDED,
                        category=t_find.category,
                        title=t_find.title,
                        base_finding=None,
                        target_finding=t_find,
                        base_severity=None,
                        target_severity=t_find.severity,
                        base_score=None,
                        target_score=t_find.score,
                        score_delta=round(float(t_find.score), 2),
                        confidence_delta=round(float(t_find.confidence), 2),
                        description=f"New finding introduced: {t_find.title} ({t_find.severity.value})",
                    )
                )
            elif t_find is None and b_find is not None:
                removed.append(
                    FindingDiff(
                        finding_key=key,
                        status=FindingDiffStatus.REMOVED,
                        category=b_find.category,
                        title=b_find.title,
                        base_finding=b_find,
                        target_finding=None,
                        base_severity=b_find.severity,
                        target_severity=None,
                        base_score=b_find.score,
                        target_score=None,
                        score_delta=round(-float(b_find.score), 2),
                        confidence_delta=round(-float(b_find.confidence), 2),
                        description=f"Finding resolved or absent: {b_find.title} (was {b_find.severity.value})",
                    )
                )
            elif b_find is not None and t_find is not None:
                score_delta = round(float(t_find.score) - float(b_find.score), 2)
                conf_delta = round(float(t_find.confidence) - float(b_find.confidence), 2)
                sev_changed = b_find.severity != t_find.severity
                score_changed = abs(score_delta) > 0.001
                conf_changed = abs(conf_delta) > 0.001

                if sev_changed or score_changed or conf_changed:
                    desc_parts = []
                    if sev_changed:
                        desc_parts.append(
                            f"Severity changed: {b_find.severity.value} -> {t_find.severity.value}"
                        )
                    if score_changed:
                        desc_parts.append(f"Score shifted: {b_find.score} -> {t_find.score}")
                    if conf_changed:
                        desc_parts.append(
                            f"Confidence shifted: {b_find.confidence} -> {t_find.confidence}"
                        )

                    modified.append(
                        FindingDiff(
                            finding_key=key,
                            status=FindingDiffStatus.MODIFIED,
                            category=t_find.category,
                            title=t_find.title,
                            base_finding=b_find,
                            target_finding=t_find,
                            base_severity=b_find.severity,
                            target_severity=t_find.severity,
                            base_score=b_find.score,
                            target_score=t_find.score,
                            score_delta=score_delta,
                            confidence_delta=conf_delta,
                            description="; ".join(desc_parts),
                        )
                    )
                else:
                    unchanged.append(
                        FindingDiff(
                            finding_key=key,
                            status=FindingDiffStatus.UNCHANGED,
                            category=t_find.category,
                            title=t_find.title,
                            base_finding=b_find,
                            target_finding=t_find,
                            base_severity=b_find.severity,
                            target_severity=t_find.severity,
                            base_score=b_find.score,
                            target_score=t_find.score,
                            score_delta=0.0,
                            confidence_delta=0.0,
                            description="Identical across both analyses",
                        )
                    )

        return added, removed, modified, unchanged

    def _compare_coverage(self, base: RiskReport, target: RiskReport) -> CoverageDiff:
        """Evaluates shifts in static and dynamic analysis depth."""
        notes: List[str] = []

        b_dex = base.dex_file_count or (
            base.static_details.dex_file_count if base.static_details else 0
        )
        t_dex = target.dex_file_count or (
            target.static_details.dex_file_count if target.static_details else 0
        )
        dex_delta = t_dex - b_dex

        b_perms = 0
        if base.permission_details and base.permission_details.declared_permissions:
            b_perms = len(base.permission_details.declared_permissions)
        elif base.static_details and base.static_details.requested_permissions:
            b_perms = len(base.static_details.requested_permissions)

        t_perms = 0
        if target.permission_details and target.permission_details.declared_permissions:
            t_perms = len(target.permission_details.declared_permissions)
        elif target.static_details and target.static_details.requested_permissions:
            t_perms = len(target.static_details.requested_permissions)

        perms_delta = t_perms - b_perms

        b_comp = 0
        if base.manifest_config:
            b_comp = base.manifest_config.exported_components_count
        elif base.static_details:
            b_comp = (
                len(base.static_details.activities)
                + len(base.static_details.services)
                + len(base.static_details.receivers)
                + len(base.static_details.providers)
            )

        t_comp = 0
        if target.manifest_config:
            t_comp = target.manifest_config.exported_components_count
        elif target.static_details:
            t_comp = (
                len(target.static_details.activities)
                + len(target.static_details.services)
                + len(target.static_details.receivers)
                + len(target.static_details.providers)
            )

        comp_delta = t_comp - b_comp

        b_dyn_st = base.module_status.get("dynamic")
        t_dyn_st = target.module_status.get("dynamic")
        dyn_depth_changed = b_dyn_st != t_dyn_st

        if dyn_depth_changed:
            notes.append(f"Dynamic analysis status changed: '{b_dyn_st}' -> '{t_dyn_st}'")

        b_profile = getattr(base, "analysis_profile", None)
        t_profile = getattr(target, "analysis_profile", None)
        if b_profile and t_profile and b_profile != t_profile:
            notes.append(f"Analysis profile shifted: '{b_profile}' -> '{t_profile}'")

        b_compat = getattr(base.compatibility_details, "overall_status", None) if base.compatibility_details else None
        if hasattr(b_compat, "value"):
            b_compat = b_compat.value
        t_compat = getattr(target.compatibility_details, "overall_status", None) if target.compatibility_details else None
        if hasattr(t_compat, "value"):
            t_compat = t_compat.value
        if b_compat and t_compat and b_compat != t_compat:
            notes.append(f"Execution compatibility shifted: '{b_compat}' -> '{t_compat}'")

        if dex_delta != 0:
            notes.append(f"DEX files analyzed delta: {dex_delta:+d} ({b_dex} -> {t_dex})")

        if perms_delta != 0:
            notes.append(f"Permissions declared delta: {perms_delta:+d} ({b_perms} -> {t_perms})")

        cov_delta = None
        if base.coverage_percent is not None and target.coverage_percent is not None:
            cov_delta = round(target.coverage_percent - base.coverage_percent, 2)

        conf_delta = None
        if base.confidence_score is not None and target.confidence_score is not None:
            conf_delta = round(target.confidence_score - base.confidence_score, 2)

        return CoverageDiff(
            base_dex_count=b_dex,
            target_dex_count=t_dex,
            dex_count_delta=dex_delta,
            base_permissions_count=b_perms,
            target_permissions_count=t_perms,
            permissions_count_delta=perms_delta,
            base_components_count=b_comp,
            target_components_count=t_comp,
            components_count_delta=comp_delta,
            base_dynamic_status=b_dyn_st,
            target_dynamic_status=t_dyn_st,
            dynamic_depth_changed=dyn_depth_changed,
            base_coverage_percent=base.coverage_percent,
            target_coverage_percent=target.coverage_percent,
            coverage_percent_delta=cov_delta,
            base_confidence_score=base.confidence_score,
            target_confidence_score=target.confidence_score,
            confidence_score_delta=conf_delta,
            notes=notes,
        )

    def _generate_summary_narrative(
        self,
        package_identity: PackageIdentityDiff,
        overall_delta: float,
        findings_summary: Dict[str, int],
        base_report: RiskReport,
        target_report: RiskReport,
    ) -> str:
        """Produces a concise human-readable comparison narrative."""
        rel = package_identity.relationship.value
        added = findings_summary.get("added", 0)
        removed = findings_summary.get("removed", 0)
        modified = findings_summary.get("modified", 0)

        if rel == AnalysisRelationship.SAME_APK_EXACT.value:
            return (
                f"Identical APK analysis comparison ({base_report.apk_filename}). "
                f"Zero score delta ({overall_delta:+.2f}). "
                f"Analysis pipeline is completely reproducible and idempotent."
            )
        elif rel == AnalysisRelationship.UNRELATED_APKS.value:
            return (
                f"Comparative evaluation of distinct packages: '{package_identity.base_package_name}' "
                f"vs '{package_identity.target_package_name}'. "
                f"Overall score delta is {overall_delta:+.2f} ({base_report.overall_score} -> {target_report.overall_score}). "
                f"Added: {added}, Removed: {removed}, Modified: {modified} findings. "
                f"WARNING: Comparisons across unrelated packages are qualitative only."
            )
        else:
            trend = "stable"
            if overall_delta > 0:
                trend = f"increased by +{overall_delta:.2f} points (higher surveillance risk)"
            elif overall_delta < 0:
                trend = f"decreased by {overall_delta:.2f} points (lower surveillance risk)"

            return (
                f"Comparison between versions of '{package_identity.base_package_name or base_report.apk_filename}'. "
                f"Risk score is {trend}. "
                f"Summary of findings: +{added} added, -{removed} removed, {modified} modified."
            )

    def generate_markdown_report(self, comp: AnalysisComparisonReport) -> str:
        """Renders an AnalysisComparisonReport as human-readable Markdown."""
        lines: List[str] = []
        lines.append(f"# SpyAware Analysis Comparison Report")
        lines.append(f"**Generated**: {comp.timestamp_comparison}")
        lines.append("")
        lines.append(f"| Aspect | Baseline Analysis | Target Analysis | Delta |")
        lines.append(f"| :--- | :--- | :--- | :--- |")
        lines.append(f"| **Analysis ID** | `{comp.base_analysis_id}` | `{comp.target_analysis_id}` | - |")
        lines.append(f"| **APK Filename** | `{comp.base_apk_filename}` | `{comp.target_apk_filename}` | - |")
        lines.append(f"| **Overall Risk Score** | **{comp.overall_score_base:.1f}** | **{comp.overall_score_target:.1f}** | **{comp.overall_score_delta:+.1f}** |")
        lines.append(f"| **Risk Classification** | `{comp.risk_level_base}` | `{comp.risk_level_target}` | - |")
        lines.append(f"| **Analysis Status** | `{comp.analysis_status_base}` | `{comp.analysis_status_target}` | - |")
        lines.append(f"| **Package Relationship** | - | - | `{comp.package_identity.relationship.value}` |")
        lines.append("")

        if comp.package_identity.warnings:
            lines.append("## Identity and Security Warnings")
            for w in comp.package_identity.warnings:
                lines.append(f"> [!WARNING]\n> {w}\n")
            lines.append("")

        lines.append("## Module Score Shifts")
        lines.append(f"| Module | Baseline Score | Target Score | Score Delta | Base Status | Target Status |")
        lines.append(f"| :--- | :--- | :--- | :--- | :--- | :--- |")
        for mod, md in comp.module_diffs.items():
            b_s = f"{md.base_score:.1f}" if md.base_score is not None else "N/A"
            t_s = f"{md.target_score:.1f}" if md.target_score is not None else "N/A"
            delta = f"{md.score_delta:+.1f}" if md.score_delta is not None else "N/A"
            lines.append(
                f"| **{mod.capitalize()}** | {b_s} | {t_s} | {delta} | `{md.base_status or 'N/A'}` | `{md.target_status or 'N/A'}` |"
            )
        lines.append("")

        lines.append("## Findings Summary")
        lines.append(
            f"- **Added Findings**: {comp.findings_summary.get('added', 0)}\n"
            f"- **Removed Findings**: {comp.findings_summary.get('removed', 0)}\n"
            f"- **Modified Findings**: {comp.findings_summary.get('modified', 0)}\n"
            f"- **Unchanged Findings**: {comp.findings_summary.get('unchanged', 0)}"
        )
        lines.append("")

        if comp.added_findings:
            lines.append("### Added Findings (+)")
            for f in comp.added_findings:
                lines.append(
                    f"- **[{f.target_severity.value if f.target_severity else 'INFO'}]** `{f.finding_key}`: {f.title} "
                    f"(Score: +{f.target_score:.1f})"
                )
                if f.target_finding and f.target_finding.evidence:
                    lines.append(f"  - *Evidence*: `{f.target_finding.evidence}`")
            lines.append("")

        if comp.removed_findings:
            lines.append("### Removed Findings (-)")
            for f in comp.removed_findings:
                lines.append(
                    f"- **[{f.base_severity.value if f.base_severity else 'INFO'}]** `{f.finding_key}`: {f.title} "
                    f"(Was score: {f.base_score:.1f})"
                )
            lines.append("")

        if comp.modified_findings:
            lines.append("### Modified Findings (Delta)")
            for f in comp.modified_findings:
                lines.append(
                    f"- `{f.finding_key}`: {f.description}"
                )
            lines.append("")

        lines.append("## Coverage & Surface Delta")
        lines.append(f"- **DEX Files**: {comp.coverage_diff.base_dex_count} -> {comp.coverage_diff.target_dex_count} (Delta: {comp.coverage_diff.dex_count_delta:+d})")
        lines.append(f"- **Permissions**: {comp.coverage_diff.base_permissions_count} -> {comp.coverage_diff.target_permissions_count} (Delta: {comp.coverage_diff.permissions_count_delta:+d})")
        lines.append(f"- **Exported Components**: {comp.coverage_diff.base_components_count} -> {comp.coverage_diff.target_components_count} (Delta: {comp.coverage_diff.components_count_delta:+d})")
        if comp.coverage_diff.notes:
            for note in comp.coverage_diff.notes:
                lines.append(f"- {note}")
        lines.append("")

        lines.append("## Summary")
        lines.append(comp.summary)
        lines.append("")

        return "\n".join(lines)
