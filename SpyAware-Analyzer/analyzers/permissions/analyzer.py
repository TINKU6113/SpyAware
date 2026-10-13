"""Dedicated Permission Analyzer for SpyAware-Analyzer.

Implements transparent, explainable weighted rule evaluation for individual
sensitive Android permissions and covert surveillance combination patterns.
"""

from typing import List, Set
from backend.models.analysis import Finding, PermissionAnalysisResult, Severity
from risk_engine.rules import (
    COMBINATION_RULES,
    INDIVIDUAL_PERMISSION_RULES,
    normalize_permission_name,
)


class PermissionAnalyzer:
    """Analyzes requested Android permissions against covert surveillance rules."""

    def __init__(self):
        self.individual_rules = INDIVIDUAL_PERMISSION_RULES
        self.combination_rules = COMBINATION_RULES

    def analyze(self, requested_permissions: List[str]) -> PermissionAnalysisResult:
        """Analyze a list of requested permissions.
        
        Args:
            requested_permissions: List of permission strings (full or short format).
            
        Returns:
            PermissionAnalysisResult with findings, combination findings, and score.
        """
        cleaned_perms: List[str] = [p.strip() for p in requested_permissions if p and p.strip()]
        normalized_set: Set[str] = {normalize_permission_name(p) for p in cleaned_perms}
        
        individual_findings: List[Finding] = []
        raw_individual_score: float = 0.0

        # Check individual permission rules
        for raw_perm in cleaned_perms:
            norm = normalize_permission_name(raw_perm)
            
            # Find matching rule either by full name or normalized suffix
            matched_rule = None
            if raw_perm in self.individual_rules:
                matched_rule = self.individual_rules[raw_perm]
            elif f"android.permission.{norm}" in self.individual_rules:
                matched_rule = self.individual_rules[f"android.permission.{norm}"]
            else:
                for rule in self.individual_rules.values():
                    if rule.short_name == norm:
                        matched_rule = rule
                        break

            if matched_rule:
                rule_key = matched_rule.short_name
                individual_findings.append(
                    Finding(
                        category="PERMISSION",
                        severity=matched_rule.severity,
                        title=f"{matched_rule.short_name}: {matched_rule.title}",
                        description=matched_rule.description,
                        evidence=f"Declared permission: {raw_perm} (Aspect: {matched_rule.surveillance_aspect})",
                        score=matched_rule.score,
                        finding_id=f"PERM_{rule_key}",
                        rule_id=f"RULE_PERM_{rule_key}",
                        confidence=1.0,
                        evidence_source="AndroidManifest.xml",
                        location="<uses-permission>",
                        security_impact=f"Enables access to {matched_rule.surveillance_aspect.lower()} data or hardware APIs.",
                        false_positive_notes="Legitimate apps with verified user requirements may declare this permission.",
                        remediation=f"Verify if the application genuinely requires {raw_perm}. Revoke or remove if not strictly necessary.",
                        detection_method="manifest_inspection",
                    )
                )
                raw_individual_score += matched_rule.score

        # Check combination rules
        combination_findings: List[Finding] = []
        raw_combo_score: float = 0.0

        for combo in self.combination_rules:
            # Check required permissions
            all_req_present = all(
                normalize_permission_name(req) in normalized_set
                for req in combo.required_permissions
            )
            if not all_req_present:
                continue

            # Check one-of groups if any
            all_one_of_satisfied = True
            matched_one_of: List[str] = []
            for group in combo.one_of_permissions:
                group_matched = [
                    opt for opt in group if normalize_permission_name(opt) in normalized_set
                ]
                if not group_matched:
                    all_one_of_satisfied = False
                    break
                matched_one_of.extend(group_matched)

            if all_one_of_satisfied:
                matched_all = list(combo.required_permissions) + matched_one_of
                combination_findings.append(
                    Finding(
                        category="PERMISSION",
                        severity=combo.severity,
                        title=f"[Pattern Synergy] {combo.title}",
                        description=combo.description,
                        evidence=f"Synergistic permission set matched: {', '.join(sorted(set(matched_all)))}",
                        score=combo.score,
                        finding_id=f"COMBO_{combo.rule_id}",
                        rule_id=f"RULE_{combo.rule_id}",
                        confidence=0.9,
                        evidence_source="AndroidManifest.xml",
                        location="<uses-permission>",
                        security_impact=combo.description,
                        false_positive_notes="Complex legitimate apps (e.g., video conferencing) may require multiple permissions legitimately.",
                        remediation="Audit combined permission capabilities to ensure sensitive dual-channel data exposure is justified.",
                        detection_method="permission_pattern_synergy",
                    )
                )
                raw_combo_score += combo.score

        # Combine all findings
        all_findings = individual_findings + combination_findings

        # Calculate normalized score (0 - 100)
        # Combination rules amplify risk; individual scores add baseline.
        # We cap at 100.0.
        total_raw = raw_individual_score + raw_combo_score
        normalized_score = min(100.0, round(total_raw, 1))

        return PermissionAnalysisResult(
            declared_permissions=cleaned_perms,
            individual_findings=individual_findings,
            combination_findings=combination_findings,
            findings=all_findings,
            score=normalized_score,
        )
