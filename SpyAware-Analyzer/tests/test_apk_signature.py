"""Tests for APK signature validation and signing certificate verification."""

from pathlib import Path
import pytest

from samples.builder import (
    find_android_build_tools,
    verify_apk_signature,
    sign_apk,
    ensure_debug_keystore,
)

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def test_benign_sample_has_valid_signing_certificate():
    """Validates that benign_sample.apk contains a verified Android signing certificate."""
    apk_path = SAMPLES_DIR / "benign_sample.apk"
    assert apk_path.exists(), "benign_sample.apk must exist in samples directory"

    verification = verify_apk_signature(apk_path)
    assert verification["verified"] is True, f"Signature verification failed: {verification['raw_output']}"
    assert verification["v2"] is True or verification["v3"] is True or verification["v1"] is True
    assert verification["signer_dn"] is not None
    assert "Android Debug" in verification["signer_dn"] or "Android" in verification["signer_dn"]
    assert verification["signer_sha256"] is not None


def test_suspicious_and_critical_samples_have_valid_signatures():
    """Validates that suspicious and critical stalkerware samples are also signed properly."""
    for sample_name in ["suspicious_surveillance_sample.apk", "critical_stalkerware_sample.apk"]:
        apk_path = SAMPLES_DIR / sample_name
        assert apk_path.exists(), f"{sample_name} must exist"

        verification = verify_apk_signature(apk_path)
        assert verification["verified"] is True, f"{sample_name} signature failed: {verification['raw_output']}"
        assert verification["signer_dn"] is not None
        assert verification["signer_sha256"] is not None


def test_positive_control_samples_have_valid_signatures():
    """Validates that positive control samples have valid Android signatures."""
    pos_samples = [
        "camera_positive_sample.apk",
        "microphone_positive_sample.apk",
        "location_positive_sample.apk",
        "service_positive_sample.apk",
    ]
    for sample_name in pos_samples:
        apk_path = SAMPLES_DIR / sample_name
        assert apk_path.exists(), f"{sample_name} must exist"

        verification = verify_apk_signature(apk_path)
        assert verification["verified"] is True, f"{sample_name} signature failed: {verification['raw_output']}"
        assert verification["signer_dn"] is not None
        assert verification["signer_sha256"] is not None


def test_ensure_debug_keystore_and_tools_discovery():
    """Validates host tools discovery and debug keystore retrieval."""
    tools = find_android_build_tools()
    assert tools["apksigner"] is not None, "apksigner must be located in Android build-tools"
    assert tools["zipalign"] is not None, "zipalign must be located in Android build-tools"

    keystore = ensure_debug_keystore()
    assert keystore.exists(), "debug.keystore must exist on disk"
