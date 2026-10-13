"""Unit and integration regression tests for Expanded Benign Test Coverage (Milestone M5).

Verifies that legitimate applications utilizing:
- Camera permissions (single-purpose camera utility)
- Location APIs (navigation/weather utility)
- Network access (secure HTTPS client)
- Dynamic reflection (Gson/Jackson/ORM deserializer)
- Dynamic code loading (modular plugin loader)
- Native libraries (game rendering engine)
- Exported Android components (public share target)

are accurately detected without being falsely categorized as malicious or elevated risk.
"""

from pathlib import Path
import pytest

from analyzers.validation.corpus import VALIDATION_CORPUS_CASES, build_validation_corpus
from backend.services.analysis_service import AnalysisService


@pytest.fixture(scope="module")
def corpus_fixtures():
    return build_validation_corpus()


@pytest.fixture
def analysis_service(tmp_path):
    return AnalysisService(reports_dir=tmp_path)


def test_tc13_legit_camera_utility(analysis_service, corpus_fixtures):
    """Legitimate single-purpose camera utility remains bounded in LOW risk."""
    apk_path = corpus_fixtures["TC_13_LEGIT_CAMERA_MIC"]
    report = analysis_service.analyze_apk_full(str(apk_path), "tc13_legit_camera.apk")

    rule_ids = {f.rule_id for f in report.findings if f.rule_id}
    assert "STATIC_DEX_CAMERA" in rule_ids
    assert "RULE_COMBO_AUDIO_VIDEO" not in rule_ids
    assert "COMBINATION_AUDIO_SURVEILLANCE" not in rule_ids
    assert "STATIC_DEX_ROOT_COMMANDS" not in rule_ids

    assert report.risk_level == "LOW"
    assert report.overall_score < 25.0


def test_tc14_legit_location_utility(analysis_service, corpus_fixtures):
    """Legitimate location app without exfiltration remains bounded in LOW risk."""
    apk_path = corpus_fixtures["TC_14_LEGIT_LOCATION"]
    report = analysis_service.analyze_apk_full(str(apk_path), "tc14_legit_location.apk")

    rule_ids = {f.rule_id for f in report.findings if f.rule_id}
    assert "STATIC_DEX_LOCATION" in rule_ids
    assert "COMBINATION_LOCATION_NETWORK_EXFILTRATION" not in rule_ids
    assert "STATIC_DEX_ROOT_COMMANDS" not in rule_ids

    assert report.risk_level == "LOW"
    assert report.overall_score < 25.0


def test_tc15_legit_network_client(analysis_service, corpus_fixtures):
    """Legitimate HTTPS network client with cleartext disabled remains bounded in LOW risk."""
    apk_path = corpus_fixtures["TC_15_LEGIT_NETWORK"]
    report = analysis_service.analyze_apk_full(str(apk_path), "tc15_legit_network.apk")

    rule_ids = {f.rule_id for f in report.findings if f.rule_id}
    assert "RULE_PERM_INTERNET" in rule_ids
    assert "STATIC_MANIFEST_CLEARTEXT_TRAFFIC" not in rule_ids
    assert "STATIC_DEX_ROOT_COMMANDS" not in rule_ids

    assert report.risk_level == "LOW"
    assert report.overall_score < 25.0


def test_tc16_legit_framework_reflection(analysis_service, corpus_fixtures):
    """Standard framework and JSON reflection remains score 6.0 LOW severity."""
    apk_path = corpus_fixtures["TC_16_LEGIT_REFLECTION"]
    report = analysis_service.analyze_apk_full(str(apk_path), "tc16_legit_reflection.apk")

    rule_ids = {f.rule_id for f in report.findings if f.rule_id}
    assert "STATIC_DEX_REFLECTION" in rule_ids
    assert "STATIC_DEX_ROOT_COMMANDS" not in rule_ids

    assert report.risk_level == "LOW"
    assert report.overall_score < 25.0


def test_tc17_legit_dynamic_plugin_loader(analysis_service, corpus_fixtures):
    """Dynamic class loader reference without surveillance synergy remains in LOW risk band."""
    apk_path = corpus_fixtures["TC_17_LEGIT_DYNAMIC_CODE"]
    report = analysis_service.analyze_apk_full(str(apk_path), "tc17_legit_dynamic_code.apk")

    rule_ids = {f.rule_id for f in report.findings if f.rule_id}
    assert "STATIC_DEX_DYNAMIC_CLASSLOADER" in rule_ids
    assert "STATIC_DEX_ROOT_COMMANDS" not in rule_ids
    assert "STATIC_DEX_CAMERA" not in rule_ids

    assert report.risk_level == "LOW"
    assert report.overall_score < 25.0


def test_tc18_legit_native_libraries(analysis_service, corpus_fixtures):
    """Legitimate game engine native shared libraries produce 0.0 score INFO finding."""
    apk_path = corpus_fixtures["TC_18_LEGIT_NATIVE_LIB"]
    report = analysis_service.analyze_apk_full(str(apk_path), "tc18_legit_native_lib.apk")

    rule_ids = {f.rule_id for f in report.findings if f.rule_id}
    assert "STATIC_NATIVE_LIBRARIES" in rule_ids
    assert "STATIC_NATIVE_DANGEROUS_IMPORTS" not in rule_ids

    assert report.risk_level == "LOW"
    assert report.overall_score == 0.0


def test_tc19_legit_exported_share_target(analysis_service, corpus_fixtures):
    """Exported share target activity with public intent filter remains in LOW risk band."""
    apk_path = corpus_fixtures["TC_19_LEGIT_EXPORTED"]
    report = analysis_service.analyze_apk_full(str(apk_path), "tc19_legit_exported.apk")

    rule_ids = {f.rule_id for f in report.findings if f.rule_id}
    assert "STATIC_MANIFEST_UNPROTECTED_EXPORTED" in rule_ids
    assert "STATIC_DEX_CAMERA" not in rule_ids

    assert report.risk_level == "LOW"
    assert report.overall_score < 25.0
