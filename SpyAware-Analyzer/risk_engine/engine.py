"""Common Risk Engine for SpyAware-Analyzer.

Aggregates findings from Static, Permission, and future analysis modules (Dynamic, Network, BLE).
Computes normalized, bounded, and explainable risk scores and classifications.
"""

from typing import Dict, List, Optional
from backend.models.analysis import Finding, ModuleScores, RiskReport, Severity


class RiskEngine:
    """Core risk evaluation and scoring engine for SpyAware-Analyzer."""

    @staticmethod
    def classify_risk_level(score: float) -> str:
        """Classify a 0-100 risk score into standard severity bands.
        
        0-24   LOW
        25-49  MEDIUM
        50-74  HIGH
        75-100 CRITICAL
        """
        score = max(0.0, min(100.0, score))
        if score < 25.0:
            return "LOW"
        elif score < 50.0:
            return "MEDIUM"
        elif score < 75.0:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def compute_peak_mean(scores: List[float]) -> float:
        """Computes peak-and-mean score: 0.60 * max(S) + 0.40 * mean(S) rounded to 1 decimal.
        
        For deduplicated non-zero finding scores S:
        - Empty: 0.0
        - Single score: s_1
        - Multiple scores: round(0.60 * max(S) + 0.40 * mean(S), 1)
        """
        pos = [float(s) for s in scores if s is not None and s > 0]
        if not pos:
            return 0.0
        if len(pos) == 1:
            return round(max(0.0, min(100.0, pos[0])), 1)
        max_s = max(pos)
        mean_s = sum(pos) / len(pos)
        return round(max(0.0, min(100.0, 0.60 * max_s + 0.40 * mean_s)), 1)

    @classmethod
    def deduplicate_findings(cls, findings: List[Finding]) -> List[Finding]:
        """Deduplicates findings by (category, title) tuple to prevent duplicate score inflation."""
        seen = set()
        deduped = []
        for f in findings:
            key = (f.category, f.title)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    @classmethod
    def calculate_score_from_findings(cls, findings: List[Finding]) -> float:
        """Computes normalized peak-and-mean score from a list of findings after deduplication."""
        deduped = cls.deduplicate_findings(findings)
        scores = [f.score for f in deduped if f.score > 0]
        return cls.compute_peak_mean(scores)

    def calculate_coverage(
        self,
        module_scores: Dict[str, Optional[float]],
        telemetry: Optional[any] = None,
    ) -> float:
        """Computes analysis coverage metric (0-100%) based on active and completed evaluation modules."""
        weights = {"static": 30.0, "permissions": 20.0, "dynamic": 30.0, "network": 20.0}
        total_coverage = 0.0
        for mod, weight in weights.items():
            if module_scores.get(mod) is not None:
                total_coverage += weight
        return round(total_coverage, 1)

    def calculate_confidence(
        self,
        coverage: float,
        findings: List[Finding],
        telemetry: Optional[any] = None,
    ) -> float:
        """Determines analysis confidence metric (0.0 to 1.0) separating evidence confidence from risk severity."""
        if coverage == 0.0:
            return 0.0
        base_confidence = min(1.0, coverage / 100.0)

        # Telemetry adjustment if dynamic was active
        if telemetry is not None:
            tested = getattr(telemetry, "categories_tested", 0)
            total = getattr(telemetry, "categories_total", 10)
            if total > 0:
                tele_ratio = tested / total
                base_confidence = round(0.50 * base_confidence + 0.50 * tele_ratio, 2)

        return max(0.1, min(1.0, round(base_confidence, 2)))

    def correlate_evidence(
        self,
        findings: List[Finding],
        telemetry: Optional[any] = None,
    ) -> Dict[str, any]:
        """Correlates static indicators (potential capabilities) with dynamic telemetry (observed behaviors).
        
        Distinguishes confirmed surveillance from dormant capabilities and unobserved permissions.
        """
        correlation: Dict[str, str] = {}
        categories_to_check = [
            ("CAMERA", "STATIC_DEX_CAMERA", "Camera"),
            ("MICROPHONE", "STATIC_DEX_AUDIO_RECORDING", "Microphone"),
            ("LOCATION", "STATIC_DEX_LOCATION", "Location"),
            ("SMS", "STATIC_DEX_SMS_CALL", "SMS / Telephony"),
            ("MEDIA_PROJECTION", "STATIC_DEX_SCREEN_CAPTURE", "Screen Capture"),
            ("ACCESSIBILITY", "STATIC_MANIFEST_ACCESSIBILITY_SERVICE", "Accessibility"),
            ("CLIPBOARD", "STATIC_DEX_CLIPBOARD_MONITORING", "Clipboard"),
            ("LOCATION", "STATIC_PERM_BACKGROUND_LOCATION", "Background Location"),
            ("PERSISTENCE", "STATIC_MANIFEST_DEVICE_ADMIN", "Device Administration"),
            ("PERSISTENCE", "STATIC_OVERLAY_WINDOW", "Overlay Window"),
        ]

        tele_categories = getattr(telemetry, "categories", {}) if telemetry else {}

        for tele_key, static_rule_key, label in categories_to_check:
            has_static = any(
                f.rule_id == static_rule_key or static_rule_key in (f.rule_id or "") or label.lower() in f.title.lower()
                for f in findings
            )
            tele_obs = tele_categories.get(tele_key)
            tele_status = tele_obs.status if tele_obs else "NOT_TESTED"

            if has_static and tele_status == "OBSERVED":
                correlation[label] = "CONFIRMED_ACTIVE_SURVEILLANCE"
            elif has_static and tele_status == "NOT_OBSERVED":
                correlation[label] = "POTENTIAL_CAPABILITY_DORMANT"
            elif not has_static and tele_status == "OBSERVED":
                correlation[label] = "UNDOCUMENTED_RUNTIME_ACTIVITY"
            elif tele_status in ("UNAVAILABLE", "NOT_TESTED"):
                correlation[label] = "INCOMPLETE_DYNAMIC_EVALUATION"
            else:
                correlation[label] = "NOT_DETECTED"

        return correlation

    def calculate_overall_risk(
        self,
        module_scores: Dict[str, Optional[float]],
        findings: List[Finding],
        telemetry: Optional[any] = None,
    ) -> Dict[str, any]:
        """Calculates bounded overall risk score from active modules and findings.
        
        Formula uses risk-weighted peak-and-mean aggregation:
        Overall = 0.60 * max(S) + 0.40 * mean(S)
        
        This prevents severe standalone surveillance indicators (e.g. Accessibility keylogger)
        from being diluted by other modules, while rewarding multi-module corroboration.
        
        Args:
            module_scores: Dict with keys 'static', 'permissions', and optionally future modules.
            findings: Aggregated list of all findings across analyzers.
            telemetry: Optional CanonicalTelemetryResult from dynamic observation.
            
        Returns:
            Dict containing overall_score, risk_level, summary, coverage, confidence, and correlation.
        """
        deduped_findings = self.deduplicate_findings(findings)
        positive_finding_scores = [f.score for f in deduped_findings if f.score > 0]

        active_scores = [v for v in module_scores.values() if v is not None]
        coverage_percent = self.calculate_coverage(module_scores, telemetry)
        confidence_score = self.calculate_confidence(coverage_percent, deduped_findings, telemetry)
        correlation_summary = self.correlate_evidence(deduped_findings, telemetry)

        if not active_scores:
            if positive_finding_scores:
                overall_score = self.compute_peak_mean(positive_finding_scores)
                risk_level = self.classify_risk_level(overall_score)
                summary = self.generate_summary(overall_score, risk_level, module_scores, deduped_findings)
                return {
                    "overall_score": overall_score,
                    "risk_level": risk_level,
                    "summary": summary,
                    "coverage_percent": coverage_percent,
                    "confidence_score": confidence_score,
                    "correlation_summary": correlation_summary,
                }
            overall_score = 0.0
            risk_level = "UNKNOWN"
            summary = self.generate_summary(overall_score, risk_level, module_scores, findings)
            return {
                "overall_score": overall_score,
                "risk_level": risk_level,
                "summary": summary,
                "coverage_percent": coverage_percent,
                "confidence_score": confidence_score,
                "correlation_summary": correlation_summary,
            }

        elif len(active_scores) == 1:
            overall_score = round(max(0.0, min(100.0, active_scores[0])), 1)
        else:
            max_score = max(active_scores)
            mean_score = sum(active_scores) / len(active_scores)
            computed = 0.60 * max_score + 0.40 * mean_score
            overall_score = round(max(0.0, min(100.0, computed)), 1)

        risk_level = self.classify_risk_level(overall_score)
        summary = self.generate_summary(overall_score, risk_level, module_scores, deduped_findings)

        return {
            "overall_score": overall_score,
            "risk_level": risk_level,
            "summary": summary,
            "coverage_percent": coverage_percent,
            "confidence_score": confidence_score,
            "correlation_summary": correlation_summary,
        }

    def generate_summary(
        self,
        overall_score: float,
        risk_level: str,
        module_scores: Dict[str, Optional[float]],
        findings: List[Finding],
    ) -> str:
        """Produces a human-readable and explainable risk summary."""
        active_scores = [v for v in module_scores.values() if v is not None]
        if not active_scores:
            return (
                "Analysis inconclusive: No active analysis modules were completed successfully. "
                "Risk score could not be determined due to execution failure or unavailable environment."
            )

        high_critical = [
            f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        
        static_score = module_scores.get("static")
        perm_score = module_scores.get("permissions")
        dynamic_score = module_scores.get("dynamic")
        network_score = module_scores.get("network")
        
        active_parts = []
        if static_score is not None:
            active_parts.append(f"Static Analysis ({static_score:.1f}/100)")
        if perm_score is not None:
            active_parts.append(f"Permission Analysis ({perm_score:.1f}/100)")
        if dynamic_score is not None:
            active_parts.append(f"Dynamic Analysis ({dynamic_score:.1f}/100)")
        if network_score is not None:
            active_parts.append(f"Network Analysis ({network_score:.1f}/100)")
        
        active_str = ", ".join(active_parts) if active_parts else "No active analyzers"

        if len(active_scores) > 1:
            max_s = max(active_scores)
            mean_s = sum(active_scores) / len(active_scores)
            score_math = f"Weighted calculation: 60% peak ({max_s:.1f}) + 40% mean ({mean_s:.1f}) = {overall_score:.1f}/100."
        else:
            score_math = f"Single active module calculation: {overall_score:.1f}/100."

        if overall_score >= 75.0:
            assessment = (
                f"CRITICAL risk ({overall_score:.1f}/100). The application exhibits high-potency "
                f"covert surveillance indicators. Observed {len(high_critical)} high/critical risk factors "
                f"such as invasive accessibility binding, stealth background persistence, or ambient sensor capture."
            )
        elif overall_score >= 50.0:
            assessment = (
                f"HIGH risk ({overall_score:.1f}/100). Observed multiple sensitive surveillance capabilities "
                f"or suspicious combination patterns across {active_str}."
            )
        elif overall_score >= 25.0:
            assessment = (
                f"MEDIUM risk ({overall_score:.1f}/100). Some privacy-impacting permissions or static capabilities "
                f"were detected, but without full overt surveillance synergy."
            )
        else:
            meaningful_findings = [f for f in findings if f.score > 0]
            if overall_score == 0.0 and len(meaningful_findings) == 0:
                assessment = (
                    f"LOW risk (0.0/100). Analysis completed with no suspicious surveillance indicators detected. "
                    f"Evaluated across {active_str}."
                )
            else:
                assessment = (
                    f"LOW risk ({overall_score:.1f}/100). Few or no sensitive surveillance indicators observed. "
                    f"Evaluated across {active_str}."
                )

        return (
            f"{assessment} {score_math} Total findings: {len(findings)} ({len(high_critical)} high/critical). "
            f"Evaluated modules: {active_str}."
        )
