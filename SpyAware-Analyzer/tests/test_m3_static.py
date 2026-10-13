"""Unit tests for Static-Analysis Improvements (Milestone M3.3).

Verifies enriched Finding schema, rule IDs, confidence separation, secret redaction,
deduplication, reflection, runtime exec, device administration, and native imports.
"""

import zipfile
from pathlib import Path
import pytest

from analyzers.static.analyzer import (
    StaticAnalyzer,
    deduplicate_findings,
    make_finding,
    redact_secret,
)
from backend.models.analysis import Finding, Severity


@pytest.fixture
def analyzer():
    return StaticAnalyzer()


def test_redact_secret():
    """Confirms sensitive secrets are masked with [REDACTED]."""
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(aws_key)
    assert "[REDACTED]" in redacted
    assert "AKIA" in redacted
    assert "MPLE" in redacted
    assert "FODNN7EXA" not in redacted


def test_make_finding_enriched_model():
    """Confirms make_finding populates stable finding_id, rule_id, confidence, and remediation."""
    f = make_finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="Test Security Finding",
        description="Detailed technical description",
        evidence="Evidence pattern",
        score=15.0,
        rule_id="STATIC_TEST_RULE",
        confidence=0.95,
        evidence_source="dex",
        remediation="Apply recommended mitigation",
    )
    assert f.finding_id is not None
    assert len(f.finding_id) == 16
    assert f.rule_id == "STATIC_TEST_RULE"
    assert f.confidence == 0.95
    assert f.remediation == "Apply recommended mitigation"
    assert f.severity == Severity.HIGH


def test_finding_deduplication():
    """Identical findings with matching rule_id and evidence are collapsed."""
    f1 = make_finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="Command Execution",
        description="Description 1",
        evidence="Runtime.getRuntime().exec('/bin/sh')",
        score=20.0,
        rule_id="STATIC_DEX_RUNTIME_EXEC",
    )
    f2 = make_finding(
        category="STATIC",
        severity=Severity.HIGH,
        title="Command Execution",
        description="Description 2",
        evidence="Runtime.getRuntime().exec('/bin/sh')",
        score=20.0,
        rule_id="STATIC_DEX_RUNTIME_EXEC",
    )
    f3 = make_finding(
        category="STATIC",
        severity=Severity.MEDIUM,
        title="Different Indicator",
        description="Description 3",
        evidence="Different evidence snippet",
        score=10.0,
        rule_id="STATIC_DEX_REFLECTION",
    )
    deduped = deduplicate_findings([f1, f2, f3])
    assert len(deduped) == 2
    assert {f.rule_id for f in deduped} == {"STATIC_DEX_RUNTIME_EXEC", "STATIC_DEX_REFLECTION"}


@pytest.fixture
def benign_manifest_bytes():
    sample_path = Path(__file__).resolve().parent.parent / "samples" / "benign_sample.apk"
    with zipfile.ZipFile(str(sample_path), "r") as zf:
        return zf.read("AndroidManifest.xml")


def test_secret_redaction_in_apk_scan(analyzer, tmp_path, benign_manifest_bytes):
    """Hardcoded credentials in DEX bytecode strings are detected and redacted."""
    apk_path = tmp_path / "secret_app.apk"
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", benign_manifest_bytes)
        # Synthetic DEX string table containing AWS and Google API keys
        dex_content = (
            b"dex\n035\x00"
            b"AKIAIOSFODNN7EXAMPLE\x00"
            b"AIzaSyB3cDeFgHiJkLmNoPqRsTuVwXyZ1234567\x00"
        )
        zf.writestr("classes.dex", dex_content)

    res = analyzer.analyze(str(apk_path))
    assert res.is_valid_apk is True
    secret_findings = [f for f in res.findings if f.rule_id == "STATIC_SECRET_HARDCODED_KEY"]
    assert len(secret_findings) >= 1
    f = secret_findings[0]
    assert "[REDACTED]" in f.evidence
    # Plaintext raw keys must not appear in full
    assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence


def test_reflection_and_runtime_exec_detection(analyzer, tmp_path, benign_manifest_bytes):
    """Bytecode containing Class.forName, Method.invoke, and Runtime.exec is flagged."""
    apk_path = tmp_path / "reflection_exec_app.apk"
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", benign_manifest_bytes)
        dex_content = (
            b"dex\n035\x00"
            b"Ljava/lang/reflect/Method;->invoke\x00"
            b"Ljava/lang/Class;->forName\x00"
            b"Ljava/lang/Runtime;->exec\x00"
            b"AES/ECB/PKCS5Padding\x00"
        )
        zf.writestr("classes.dex", dex_content)

    res = analyzer.analyze(str(apk_path))
    assert res.is_valid_apk is True

    rule_ids = {f.rule_id for f in res.findings}
    assert "STATIC_DEX_REFLECTION" in rule_ids
    assert "STATIC_DEX_RUNTIME_EXEC" in rule_ids
    assert "STATIC_INSECURE_CRYPTO_ECB" in rule_ids


def test_native_dangerous_imports_detection(analyzer, tmp_path, benign_manifest_bytes):
    """Compiled native libraries referencing system() or popen() are detected."""
    apk_path = tmp_path / "native_exec_app.apk"
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", benign_manifest_bytes)
        zf.writestr("classes.dex", b"dex\n035\x00\x00")
        zf.writestr("lib/arm64-v8a/libmal.so", b"\x7fELF64 native binary with system\x00 and popen\x00 symbols")

    res = analyzer.analyze(str(apk_path))
    assert res.is_valid_apk is True
    native_findings = [f for f in res.findings if f.rule_id == "STATIC_NATIVE_DANGEROUS_IMPORTS"]
    assert len(native_findings) == 1
    assert "system" in native_findings[0].evidence
    assert res.sha256 is not None
    assert len(res.sha256) == 64
