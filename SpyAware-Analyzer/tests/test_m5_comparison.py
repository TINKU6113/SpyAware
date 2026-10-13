"""Unit and integration tests for Historical Analysis Comparison in M5.

Validates:
- Exact zero-diff / idempotent results for identical APK re-analyses.
- Minor version update tracking with added/removed permissions and findings.
- Major behavior change detection with score and factor shift tracking.
- Package identity integrity checks: unrelated APK warnings, cert mismatches, and SDK downgrades.
- Reusable Markdown report rendering.
- FastAPI REST endpoints: POST /api/analyses/compare and GET markdown export.
"""

import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.analysis import (
    CertificateInfo,
    Finding,
    ManifestConfiguration,
    ModuleScores,
    RiskReport,
    Severity,
    StaticAnalysisResult,
)
from backend.models.comparison import (
    AnalysisRelationship,
    FindingDiffStatus,
)
from backend.services.comparison_service import ComparisonService, get_stable_finding_key


def _create_sample_report(
    analysis_id: str,
    apk_filename: str,
    package_name: str,
    version_name: str = "1.0.0",
    sha256: str = "aaaabbbbccccdddd1111222233334444555566667777888899990000aaaabbbb",
    overall_score: float = 10.0,
    risk_level: str = "LOW",
    findings: list = None,
    cert_sha256: str = "cert_hash_1111",
    target_sdk: str = "34",
    dynamic_status: str = "COMPLETED",
) -> RiskReport:
    """Helper to assemble a complete valid RiskReport."""
    f_list = findings or []
    static_res = StaticAnalysisResult(
        apk_filename=apk_filename,
        package_name=package_name,
        app_name="SampleApp",
        version_name=version_name,
        version_code="1",
        min_sdk="21",
        target_sdk=target_sdk,
        requested_permissions=["android.permission.INTERNET"],
        activities=["com.example.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        exported_components=[],
        dex_file_count=1,
        dex_files_analyzed=["classes.dex"],
        score=overall_score,
        is_valid_apk=True,
        sha256=sha256,
    )
    cert_info = CertificateInfo(
        is_signed=True,
        sha256_fingerprint=cert_sha256,
        is_debug_key=False,
    )
    manifest_cfg = ManifestConfiguration(
        debuggable=False,
        allow_backup=True,
        exported_components_count=1,
    )
    mod_scores = ModuleScores(
        static=overall_score,
        permissions=5.0,
        dynamic=0.0 if dynamic_status == "COMPLETED" else None,
        network=None,
        ble=None,
    )
    mod_status = {
        "static": "COMPLETED",
        "permissions": "COMPLETED",
        "dynamic": dynamic_status,
        "network": "NOT_REQUESTED",
        "ble": "NOT_IMPLEMENTED",
    }

    return RiskReport(
        analysis_id=analysis_id,
        timestamp="2026-10-11T20:00:00Z",
        apk_filename=apk_filename,
        overall_score=overall_score,
        risk_level=risk_level,
        analysis_status="COMPLETED_WITH_FINDINGS" if f_list else "COMPLETED_CLEAN",
        module_scores=mod_scores,
        module_status=mod_status,
        findings=f_list,
        summary="Automated test report summary",
        static_details=static_res,
        certificate_info=cert_info,
        manifest_config=manifest_cfg,
        sha256=sha256,
        dex_file_count=1,
        coverage_percent=85.0,
        confidence_score=0.90,
    )


def test_stable_finding_key_generation():
    """Verify that finding key normalization is deterministic across instances."""
    f1 = Finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="DEX Dynamic Code Loading via DexClassLoader",
        description="Loads code",
        evidence="DexClassLoader found",
        score=20.0,
        rule_id="STATIC_DEX_DYNAMIC_LOADING",
        location="com.example.PluginManager",
    )
    f2 = Finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="DEX Dynamic Code Loading via DexClassLoader",
        description="Loads code",
        evidence="DexClassLoader found",
        score=20.0,
        rule_id="STATIC_DEX_DYNAMIC_LOADING",
        location="com.example.PluginManager",
    )
    assert get_stable_finding_key(f1) == "STATIC_DEX_DYNAMIC_LOADING@com.example.pluginmanager"
    assert get_stable_finding_key(f1) == get_stable_finding_key(f2)


def test_identical_apk_reanalysis_zero_diff():
    """Re-analyzing the exact same APK yields a zero-diff idempotent comparison."""
    comp_svc = ComparisonService()
    f1 = Finding(
        category="PERMISSION",
        severity=Severity.LOW,
        title="Network Access Permission",
        description="Allows network access",
        evidence="INTERNET requested",
        score=5.0,
        rule_id="PERM_INTERNET",
    )
    rep1 = _create_sample_report("id_001", "app_v1.apk", "com.example.app", findings=[f1])
    rep2 = _create_sample_report("id_002", "app_v1.apk", "com.example.app", findings=[f1])

    comp = comp_svc.compare_analyses(rep1, rep2)

    assert comp.package_identity.relationship == AnalysisRelationship.SAME_APK_EXACT
    assert comp.overall_score_delta == 0.0
    assert comp.is_unrelated_warning is False
    assert comp.findings_summary["added"] == 0
    assert comp.findings_summary["removed"] == 0
    assert comp.findings_summary["modified"] == 0
    assert comp.findings_summary["unchanged"] == 1
    assert len(comp.unchanged_findings) == 1
    assert comp.unchanged_findings[0].status == FindingDiffStatus.UNCHANGED
    assert "idempotent" in comp.summary.lower()


def test_minor_version_update_tracking():
    """Minor app version bump with a new permission and resolved issue is clearly categorized."""
    comp_svc = ComparisonService()
    f_perm = Finding(
        category="PERMISSION",
        severity=Severity.LOW,
        title="Network Access",
        evidence="INTERNET",
        score=5.0,
        rule_id="PERM_INTERNET",
        description="Net access",
    )
    f_cam = Finding(
        category="PERMISSION",
        severity=Severity.MEDIUM,
        title="Camera Access",
        evidence="CAMERA",
        score=15.0,
        rule_id="PERM_CAMERA",
        description="Cam access",
    )

    rep_v1 = _create_sample_report(
        "id_v1", "app_v1.apk", "com.example.app",
        version_name="1.0.0", sha256="hash1111",
        overall_score=5.0, findings=[f_perm]
    )
    rep_v2 = _create_sample_report(
        "id_v2", "app_v2.apk", "com.example.app",
        version_name="1.1.0", sha256="hash2222",
        overall_score=20.0, findings=[f_perm, f_cam]
    )

    comp = comp_svc.compare_analyses(rep_v1, rep_v2)

    assert comp.package_identity.relationship == AnalysisRelationship.SAME_PACKAGE_VERSION_UPDATE
    assert comp.package_identity.is_version_changed is True
    assert comp.overall_score_delta == 15.0
    assert comp.findings_summary["added"] == 1
    assert comp.findings_summary["removed"] == 0
    assert comp.findings_summary["unchanged"] == 1
    assert comp.added_findings[0].finding_key == "PERM_CAMERA"
    assert comp.added_findings[0].score_delta == 15.0


def test_major_behavior_change_with_modified_findings():
    """Shift where finding severity increases or findings are modified reflects proper deltas."""
    comp_svc = ComparisonService()
    f_old = Finding(
        category="STATIC",
        severity=Severity.LOW,
        title="Reflection Usage",
        evidence="Class.forName() found",
        score=5.0,
        rule_id="STATIC_DEX_REFLECTION",
        description="Standard reflection",
    )
    f_new = Finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="Reflection Usage",
        evidence="Dangerous Method.invoke() on hidden APIs found",
        score=25.0,
        rule_id="STATIC_DEX_REFLECTION",
        description="Evasive reflection pattern",
    )

    rep1 = _create_sample_report("id_m1", "app.apk", "com.example.app", overall_score=5.0, findings=[f_old])
    rep2 = _create_sample_report("id_m2", "app.apk", "com.example.app", overall_score=25.0, findings=[f_new])

    comp = comp_svc.compare_analyses(rep1, rep2)

    assert comp.findings_summary["modified"] == 1
    assert len(comp.modified_findings) == 1
    mod = comp.modified_findings[0]
    assert mod.status == FindingDiffStatus.MODIFIED
    assert mod.base_severity == Severity.LOW
    assert mod.target_severity == Severity.HIGH
    assert mod.score_delta == 20.0
    assert "Severity changed: LOW -> HIGH" in mod.description


def test_unrelated_packages_trigger_prominent_warning():
    """Comparing two different package names produces UNRELATED_APKS and prominent warnings."""
    comp_svc = ComparisonService()
    repA = _create_sample_report("id_A", "calc.apk", "com.calculator.tool", sha256="hash_calc_1234", overall_score=0.0)
    repB = _create_sample_report("id_B", "stalker.apk", "com.spyware.tracker", sha256="hash_stalker_5678", overall_score=85.0)

    comp = comp_svc.compare_analyses(repA, repB)

    assert comp.package_identity.relationship == AnalysisRelationship.UNRELATED_APKS
    assert comp.is_unrelated_warning is True
    assert len(comp.package_identity.warnings) > 0
    assert any("UNRELATED APPLICATION WARNING" in w for w in comp.package_identity.warnings)


def test_certificate_and_target_sdk_downgrade_warnings():
    """Flag certificate substitutions and targetSdk downgrades."""
    comp_svc = ComparisonService()
    rep1 = _create_sample_report(
        "id_cert1", "v1.apk", "com.example.app",
        cert_sha256="ORIGINAL_CERT_HASH", target_sdk="34"
    )
    rep2 = _create_sample_report(
        "id_cert2", "v2.apk", "com.example.app",
        cert_sha256="SUSPICIOUS_NEW_CERT", target_sdk="28"
    )

    comp = comp_svc.compare_analyses(rep1, rep2)

    assert comp.package_identity.is_cert_changed is True
    warn_text = " ".join(comp.package_identity.warnings)
    assert "SIGNING CERTIFICATE MISMATCH" in warn_text
    assert "TARGET SDK DOWNGRADE DETECTED" in warn_text


def test_coverage_and_dynamic_depth_delta():
    """Shifts in dynamic sandbox status and tested surface are detected."""
    comp_svc = ComparisonService()
    rep_static = _create_sample_report(
        "id_s", "app.apk", "com.example.app", dynamic_status="NOT_REQUESTED"
    )
    rep_dynamic = _create_sample_report(
        "id_d", "app.apk", "com.example.app", dynamic_status="COMPLETED"
    )

    comp = comp_svc.compare_analyses(rep_static, rep_dynamic)

    assert comp.coverage_diff.dynamic_depth_changed is True
    assert any("Dynamic analysis status changed" in n for n in comp.coverage_diff.notes)


def test_markdown_report_formatting():
    """Verify Markdown report generation formats clean markdown tables and alerts."""
    comp_svc = ComparisonService()
    f = Finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="Dynamic Code Loading",
        evidence="DexClassLoader",
        score=20.0,
        rule_id="STATIC_DEX_DYNAMIC_LOADING",
        description="Loads code",
    )
    rep1 = _create_sample_report("id_r1", "app_v1.apk", "com.example.app", findings=[])
    rep2 = _create_sample_report("id_r2", "app_v2.apk", "com.example.app", findings=[f], overall_score=20.0)

    comp = comp_svc.compare_analyses(rep1, rep2)
    md = comp_svc.generate_markdown_report(comp)

    assert "# SpyAware Analysis Comparison Report" in md
    assert "| **Overall Risk Score** |" in md
    assert "### Added Findings (+)" in md
    assert "STATIC_DEX_DYNAMIC_LOADING" in md


def test_api_comparison_endpoints(tmp_path):
    """Test POST /api/analyses/compare and GET export markdown via FastAPI TestClient."""
    from backend.api.router import analysis_service

    # Point analysis_service to temporary reports directory
    orig_reports_dir = analysis_service.reports_dir
    analysis_service.reports_dir = tmp_path
    analysis_service.reports_dir.mkdir(parents=True, exist_ok=True)

    try:
        rep1 = _create_sample_report("test_base_001", "base.apk", "com.test.app", overall_score=10.0)
        rep2 = _create_sample_report("test_target_002", "target.apk", "com.test.app", overall_score=30.0)
        analysis_service.save_report(rep1)
        analysis_service.save_report(rep2)

        client = TestClient(app)

        # 1. POST /api/analyses/compare
        resp = client.post(
            "/api/analyses/compare",
            json={"base_analysis_id": "test_base_001", "target_analysis_id": "test_target_002"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["base_analysis_id"] == "test_base_001"
        assert data["target_analysis_id"] == "test_target_002"
        assert data["overall_score_delta"] == 20.0

        # 2. GET /api/analyses/compare/{base}/{target}/export/markdown
        md_resp = client.get(
            "/api/analyses/compare/test_base_001/test_target_002/export/markdown"
        )
        assert md_resp.status_code == 200
        assert "# SpyAware Analysis Comparison Report" in md_resp.text

        # 3. Nonexistent report check
        err_resp = client.post(
            "/api/analyses/compare",
            json={"base_analysis_id": "nonexistent_999", "target_analysis_id": "test_target_002"},
        )
        assert err_resp.status_code == 404
    finally:
        analysis_service.reports_dir = orig_reports_dir
