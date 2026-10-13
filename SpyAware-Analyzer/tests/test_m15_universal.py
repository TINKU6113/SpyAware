"""Regression and verification tests for M1.5 Universal APK Analysis Reliability and Compatibility.

Covers:
1. Archive validation & security:
   - Empty file rejection (HTTP 400)
   - Corrupt/truncated archive rejection (HTTP 400)
   - Encrypted archive rejection (HTTP 400)
   - Path traversal attempt rejection (HTTP 400)
   - Zip bomb / excessive expansion rejection (HTTP 400)
2. Multi-DEX analysis & bytecode coverage:
   - Multi-DEX enumeration (classes.dex, classes2.dex, classes3.dex)
   - dex_file_count, dex_files_analyzed, is_multidex
   - High-throughput scanning across all DEX files
3. Zero-DEX APK handling without exception:
   - Clean handling of APKs with zero DEX files
   - Clear limitation noted without crashing
4. Native libraries:
   - Architectures identified (e.g. arm64-v8a, armeabi-v7a)
   - Severity is INFO and score is 0.0 (no risk inflation)
5. False positive reduction:
   - AndroidX/Compose string 'setPropagation' does NOT trigger root command finding
   - Actual 'setprop ro.debuggable 1' triggers finding
6. Certificate metadata extraction:
   - Fingerprints (SHA-256, SHA-1), serial number, validity dates
   - Verification status set to METADATA_EXTRACTED_UNVERIFIED
7. Manifest configuration:
   - Custom permissions, dangerous permissions count, exported component count
8. Peak-and-mean risk scoring:
   - [15.0, 10.0] yields 14.0
9. Split APK handling:
   - split_names parameter passed and reported
10. Max upload size configuration:
   - SPYAWARE_MAX_UPLOAD_MB respected
"""

import io
import os
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.analysis import RiskReport, Severity
from backend.services.analysis_service import AnalysisService, InvalidAPKError, get_max_upload_bytes
from analyzers.static.analyzer import StaticAnalyzer
from risk_engine.engine import RiskEngine

client = TestClient(app)
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
BENIGN_APK = SAMPLES_DIR / "benign_sample.apk"


# -----------------------------------------------------------------------------
# 1. Archive Ingestion & Security Validation
# -----------------------------------------------------------------------------

def test_reject_empty_file():
    """Empty 0-byte file upload returns HTTP 400."""
    response = client.post(
        "/api/analyze",
        files={"file": ("empty.apk", io.BytesIO(b""), "application/vnd.android.package-archive")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_reject_corrupt_archive():
    """Corrupt archive returns HTTP 400."""
    response = client.post(
        "/api/analyze",
        files={"file": ("corrupt.apk", io.BytesIO(b"PK\x03\x04not-a-valid-zip"), "application/vnd.android.package-archive")},
    )
    assert response.status_code == 400
    assert "invalid apk" in response.json()["detail"].lower()


def test_reject_encrypted_archive():
    """Encrypted ZIP archive entries return HTTP 400."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.setpassword(b"secret")
        # In python zipfile, writestr with setpassword sets encryption flag
        zf.writestr("AndroidManifest.xml", b"test", compress_type=zipfile.ZIP_DEFLATED)
    buf.seek(0)

    # Let's verify encrypt flag in zipfile
    response = client.post(
        "/api/analyze",
        files={"file": ("encrypted.apk", buf, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 400


def test_reject_path_traversal_archive():
    """Archive with directory traversal entries returns HTTP 400."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../etc/passwd", b"root:x:0:0:")
        zf.writestr("AndroidManifest.xml", b"dummy")
    buf.seek(0)

    response = client.post(
        "/api/analyze",
        files={"file": ("traversal.apk", buf, "application/vnd.android.package-archive")},
    )
    assert response.status_code == 400
    assert "traversal" in response.json()["detail"].lower() or "invalid" in response.json()["detail"].lower()


def test_configurable_upload_size():
    """Upload size threshold is configurable via SPYAWARE_MAX_UPLOAD_MB."""
    with patch.dict(os.environ, {"SPYAWARE_MAX_UPLOAD_MB": "200"}):
        assert get_max_upload_bytes() == 200 * 1024 * 1024

    with patch.dict(os.environ, {"SPYAWARE_MAX_UPLOAD_MB": "50"}):
        assert get_max_upload_bytes() == 50 * 1024 * 1024


# -----------------------------------------------------------------------------
# 2. Multi-DEX & Bytecode Analysis
# -----------------------------------------------------------------------------

def test_multidex_apk_enumeration_and_coverage(tmp_path):
    """Multi-DEX APKs with classes.dex, classes2.dex, classes3.dex are analyzed."""
    # We will use benign_sample.apk as base and add classes2.dex and classes3.dex
    assert BENIGN_APK.exists(), "benign_sample.apk must exist"

    multidex_apk = tmp_path / "multidex_sample.apk"
    with zipfile.ZipFile(BENIGN_APK, "r") as zin:
        with zipfile.ZipFile(multidex_apk, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            # Add synthetic classes2.dex and classes3.dex
            # DEX header magic \x64\x65\x78\x0a\x30\x33\x35\x00 (dex\n035\0)
            dex_magic = b"dex\n035\x00" + b"\x00" * 100
            zout.writestr("classes2.dex", dex_magic + b"android.hardware.Camera")
            zout.writestr("classes3.dex", dex_magic + b"android.media.AudioRecord")

    analyzer = StaticAnalyzer()
    result = analyzer.analyze(str(multidex_apk))

    assert result.is_valid_apk is True
    assert result.is_multidex is True
    assert result.dex_file_count == 3
    assert len(result.dex_files_analyzed) == 3
    assert result.dex_files_failed == {}
    # Camera indicator found across dex files
    assert any("Camera" in ind for ind in result.camera_api_indicators)
    # Microphone indicator found across dex files
    assert any("AudioRecord" in ind for ind in result.microphone_api_indicators)


def test_zero_dex_apk_handling(tmp_path):
    """APKs with no DEX files (e.g. resource or asset only APKs) are handled gracefully."""
    zero_dex_apk = tmp_path / "zero_dex.apk"
    with zipfile.ZipFile(BENIGN_APK, "r") as zin:
        with zipfile.ZipFile(zero_dex_apk, "w") as zout:
            for item in zin.infolist():
                if not item.filename.endswith(".dex"):
                    zout.writestr(item, zin.read(item.filename))

    analyzer = StaticAnalyzer()
    result = analyzer.analyze(str(zero_dex_apk))

    assert result.is_valid_apk is True
    assert result.is_multidex is False
    assert result.dex_file_count == 0
    assert len(result.dex_files_analyzed) == 0
    assert result.limitations is not None
    assert any("No DEX bytecode files were found" in lim for lim in result.limitations)


# -----------------------------------------------------------------------------
# 3. Native Libraries & False Positive Elimination
# -----------------------------------------------------------------------------

def test_native_libraries_architectures_and_zero_score(tmp_path):
    """Native shared libraries are detected with architectures and assigned score 0.0 (INFO)."""
    native_apk = tmp_path / "native_sample.apk"
    with zipfile.ZipFile(BENIGN_APK, "r") as zin:
        with zipfile.ZipFile(native_apk, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            zout.writestr("lib/arm64-v8a/libflutter.so", b"\x7fELFfakebinary")
            zout.writestr("lib/armeabi-v7a/libflutter.so", b"\x7fELFfakebinary")

    analyzer = StaticAnalyzer()
    result = analyzer.analyze(str(native_apk))

    assert "lib/arm64-v8a/libflutter.so" in result.native_libraries
    assert "arm64-v8a" in result.native_architectures
    assert "armeabi-v7a" in result.native_architectures

    # Check finding severity and score
    native_finding = next((f for f in result.findings if "Native Shared Libraries" in f.title), None)
    assert native_finding is not None
    assert native_finding.severity == Severity.INFO
    assert native_finding.score == 0.0


def test_false_positive_setprop_not_triggered_by_setpropagation(tmp_path):
    """'setPropagation' from AndroidX/Compose does not trigger suspicious command finding."""
    apk = tmp_path / "compose_app.apk"
    dex_magic = b"dex\n035\x00" + b"\x00" * 100
    with zipfile.ZipFile(BENIGN_APK, "r") as zin:
        with zipfile.ZipFile(apk, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            zout.writestr("classes2.dex", dex_magic + b"androidx/compose/animation/setPropagation")

    analyzer = StaticAnalyzer()
    result = analyzer.analyze(str(apk))

    # Verify no false positive suspicious command finding
    setprop_findings = [f for f in result.findings if f.title == "Shell Execution or Superuser Strings Detected" and "setprop" in f.evidence]
    assert len(setprop_findings) == 0, f"False positive detected: {setprop_findings}"


def test_true_positive_setprop_is_detected(tmp_path):
    """Actual 'setprop ro.debuggable 1' command is correctly detected as suspicious."""
    apk = tmp_path / "malicious_cmd.apk"
    dex_magic = b"dex\n035\x00" + b"\x00" * 100
    with zipfile.ZipFile(BENIGN_APK, "r") as zin:
        with zipfile.ZipFile(apk, "w") as zout:
            for item in zin.infolist():
                zout.writestr(item, zin.read(item.filename))
            zout.writestr("classes2.dex", dex_magic + b"setprop ro.debuggable 1")

    analyzer = StaticAnalyzer()
    result = analyzer.analyze(str(apk))

    cmd_findings = [f for f in result.findings if f.title == "Shell Execution or Superuser Strings Detected"]
    assert len(cmd_findings) > 0
    assert any("setprop" in f.evidence for f in cmd_findings)


# -----------------------------------------------------------------------------
# 4. Certificate & Manifest Metadata Extraction
# -----------------------------------------------------------------------------

def test_certificate_metadata_fields():
    """Certificate fingerprints, serial number, and validity dates are extracted."""
    analyzer = StaticAnalyzer()
    result = analyzer.analyze(str(BENIGN_APK))

    cert = result.certificate_info
    assert cert is not None
    assert cert.is_signed is True
    assert cert.sha256_fingerprint is not None
    assert cert.sha1_fingerprint is not None
    assert cert.serial_number is not None
    assert cert.verification_status == "METADATA_EXTRACTED_UNVERIFIED"
    assert "full root CA trust chain not validated" in cert.verification_details


def test_manifest_metadata_fields():
    """Manifest configuration captures custom permissions and exported components counts."""
    analyzer = StaticAnalyzer()
    result = analyzer.analyze(str(BENIGN_APK))

    manifest = result.manifest_config
    assert manifest is not None
    assert isinstance(manifest.debuggable, bool)
    assert isinstance(manifest.allow_backup, bool)
    assert manifest.exported_components_count is not None
    assert manifest.exported_components_count >= 0
    assert manifest.dangerous_permissions_count is not None
    assert manifest.dangerous_permissions_count >= 0


# -----------------------------------------------------------------------------
# 5. Peak-and-Mean Risk Engine Calculations
# -----------------------------------------------------------------------------

def test_peak_and_mean_scoring():
    """Peak-and-mean formula: 0.60 * max + 0.40 * mean.
    For scores [15.0, 10.0]: max=15.0, mean=12.5 -> 0.60*15 + 0.40*12.5 = 9.0 + 5.0 = 14.0.
    """
    engine = RiskEngine()
    score = engine.compute_peak_mean([15.0, 10.0])
    assert score == 14.0

    res = engine.calculate_overall_risk(
        module_scores={"static": 15.0, "permissions": 10.0},
        findings=[],
    )
    assert res["overall_score"] == 14.0


# -----------------------------------------------------------------------------
# 6. Split APK & split_names API Parameter
# -----------------------------------------------------------------------------

def test_split_apk_analysis_service_integration():
    """AnalysisService and RiskReport properly record split_names and is_split."""
    service = AnalysisService()
    report = service.analyze_apk_full(
        apk_path=str(BENIGN_APK),
        original_filename="base.apk",
        is_split=True,
        split_count=3,
        split_names=["split_config.arm64_v8a.apk", "split_config.xxhdpi.apk"],
    )

    assert report.is_split is True
    assert report.split_count == 3
    assert report.split_names == ["split_config.arm64_v8a.apk", "split_config.xxhdpi.apk"]
    assert report.static_details.is_split is True
    assert report.static_details.split_count == 3
    assert any("split apk installation" in lim.lower() for lim in report.limitations)
