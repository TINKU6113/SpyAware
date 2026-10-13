"""Regression and capability unit tests for Milestone M3.0 (Universal APK Intake & Validation)."""

import hashlib
import io
import os
import tempfile
import zipfile
import pytest
from pathlib import Path

from analyzers.intake.validator import UniversalAPKIntake
from analyzers.intake.models import IntakeStatus, FrameworkType


@pytest.fixture
def intake():
    return UniversalAPKIntake(max_file_size_bytes=10 * 1024 * 1024)  # 10 MB for test


@pytest.fixture
def benign_apk_path():
    path = Path(__file__).resolve().parent.parent / "samples" / "benign_sample.apk"
    if not path.exists():
        pytest.skip("benign_sample.apk not found in samples")
    return str(path)


def test_valid_benign_apk_intake(intake, benign_apk_path):
    result = intake.validate_and_intake(benign_apk_path)
    assert result.is_valid is True
    assert result.status in (IntakeStatus.VALID, IntakeStatus.VALID_WITH_WARNINGS)
    assert result.hashes is not None
    assert len(result.hashes.sha256) == 64
    assert len(result.hashes.sha1) == 40
    assert len(result.hashes.md5) == 32
    assert result.metadata is not None
    assert result.metadata.package_name == "com.spyaware.benign"
    assert result.metadata.min_sdk is not None
    assert result.metadata.target_sdk is not None
    assert result.framework.framework == FrameworkType.JAVA_KOTLIN
    assert result.dex_file_count >= 1


def test_nonexistent_file_intake(intake):
    result = intake.validate_and_intake("/nonexistent/path/to/app.apk")
    assert result.is_valid is False
    assert result.status == IntakeStatus.NOT_FOUND
    assert "does not exist" in result.errors[0]


def test_empty_file_intake(intake, tmp_path):
    empty_file = tmp_path / "empty.apk"
    empty_file.write_bytes(b"")
    result = intake.validate_and_intake(str(empty_file))
    assert result.is_valid is False
    assert result.status == IntakeStatus.EMPTY_FILE
    assert result.file_size_bytes == 0


def test_file_too_large_intake(tmp_path):
    small_limit_intake = UniversalAPKIntake(max_file_size_bytes=1024)  # 1KB limit
    large_file = tmp_path / "large.apk"
    large_file.write_bytes(b"A" * 2048)  # 2KB
    result = small_limit_intake.validate_and_intake(str(large_file))
    assert result.is_valid is False
    assert result.status == IntakeStatus.FILE_TOO_LARGE


def test_invalid_archive_format(intake, tmp_path):
    not_a_zip = tmp_path / "fake.apk"
    not_a_zip.write_bytes(b"This is a text string, not a valid zip archive.")
    result = intake.validate_and_intake(str(not_a_zip))
    assert result.is_valid is False
    assert result.status == IntakeStatus.INVALID_ARCHIVE
    assert result.hashes is not None


def test_zip_without_manifest(intake, tmp_path):
    zip_path = tmp_path / "no_manifest.apk"
    with zipfile.ZipFile(str(zip_path), "w") as zf:
        zf.writestr("classes.dex", b"dex\n035\x00")
        zf.writestr("res/layout/main.xml", b"<layout></layout>")
    result = intake.validate_and_intake(str(zip_path))
    assert result.is_valid is False
    assert result.status == IntakeStatus.INVALID_ARCHIVE
    assert any("missing required AndroidManifest.xml" in e for e in result.errors)


def test_path_traversal_detection(intake, tmp_path):
    traversal_zip = tmp_path / "traversal.apk"
    with zipfile.ZipFile(str(traversal_zip), "w") as zf:
        zf.writestr("../etc/passwd", b"root:x:0:0:")
        zf.writestr("AndroidManifest.xml", b"manifest content")
    result = intake.validate_and_intake(str(traversal_zip))
    assert result.is_valid is False
    assert result.status == IntakeStatus.PATH_TRAVERSAL
    assert any("path traversal" in e for e in result.errors)


def test_native_abi_detection(intake, tmp_path):
    apk_path = tmp_path / "native.apk"
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", b"binary manifest")
        zf.writestr("classes.dex", b"dex bytecode")
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF64 native code")
        zf.writestr("lib/x86_64/libnative.so", b"\x7fELF64 native code")
    result = intake.validate_and_intake(str(apk_path))
    assert result.has_native_libraries is True
    assert "arm64-v8a" in result.native_abis
    assert "x86_64" in result.native_abis


def test_flutter_framework_detection(intake, tmp_path):
    apk_path = tmp_path / "flutter_sample.apk"
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", b"binary manifest")
        zf.writestr("classes.dex", b"dex bytecode")
        zf.writestr("lib/arm64-v8a/libflutter.so", b"\x7fELF flutter engine")
        zf.writestr("assets/flutter_assets/kernel_blob.bin", b"flutter kernel")
    result = intake.validate_and_intake(str(apk_path))
    assert result.framework.framework == FrameworkType.FLUTTER
    assert result.framework.confidence >= 0.90


def test_react_native_framework_detection(intake, tmp_path):
    apk_path = tmp_path / "rn_sample.apk"
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", b"binary manifest")
        zf.writestr("classes.dex", b"dex bytecode")
        zf.writestr("lib/arm64-v8a/libreactnativejni.so", b"\x7fELF rn jni")
        zf.writestr("assets/index.android.bundle", b"console.log('RN app');")
    result = intake.validate_and_intake(str(apk_path))
    assert result.framework.framework == FrameworkType.REACT_NATIVE
    assert result.framework.confidence >= 0.90


def test_unity_framework_detection(intake, tmp_path):
    apk_path = tmp_path / "unity_sample.apk"
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", b"binary manifest")
        zf.writestr("classes.dex", b"dex bytecode")
        zf.writestr("lib/arm64-v8a/libunity.so", b"\x7fELF unity engine")
        zf.writestr("assets/bin/Data/mainData", b"unity main binary data")
    result = intake.validate_and_intake(str(apk_path))
    assert result.framework.framework == FrameworkType.UNITY
    assert result.framework.confidence >= 0.90


def test_known_packer_detection(intake, tmp_path):
    apk_path = tmp_path / "packed.apk"
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", b"binary manifest")
        zf.writestr("classes.dex", b"dex bytecode")
        zf.writestr("lib/arm64-v8a/libprotectClass.so", b"\x7fELF qihoo 360")
    result = intake.validate_and_intake(str(apk_path))
    assert result.packing_info.is_packed is True
    assert "Qihoo 360" in result.packing_info.packer_name


def test_hash_consistency(intake, tmp_path):
    content = b"TEST CONTENT FOR HASH VERIFICATION 12345"
    test_file = tmp_path / "hash_test.apk"
    test_file.write_bytes(content)

    hashes = intake.calculate_hashes(str(test_file))
    assert hashes.sha256 == hashlib.sha256(content).hexdigest()
    assert hashes.sha1 == hashlib.sha1(content).hexdigest()
    assert hashes.md5 == hashlib.md5(content).hexdigest()
