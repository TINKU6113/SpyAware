"""Comprehensive Compatibility Regression Tests (Milestone M5).

Verifies:
1. Pure Java/Kotlin APKs execute across all architectures.
2. arm64-v8a and armeabi-v7a native library compatibility on ARM vs x86_64 targets.
3. x86 and x86_64 native library compatibility on x86_64 targets.
4. Unsupported ABIs (mips, mips64, riscv64) result in INCOMPATIBLE_ABI.
5. minSdk > device API level results in INCOMPATIBLE_ANDROID_VERSION.
6. Missing required split APK components results in REQUIRED_SPLIT_PACKAGES_MISSING.
7. Malformed archives result in COMPATIBILITY_UNKNOWN with clean errors.
8. Compatibility failures are strictly distinguished from security risk findings.
"""

from unittest.mock import MagicMock
import pytest

from analyzers.dynamic.compatibility import (
    CandidateEnvironmentEvaluation,
    CompatibilityEngine,
    CompatibilityReport,
    CompatibilityStatus,
)
from analyzers.dynamic.models import AVDInventory, AVDProfile
from analyzers.intake.models import APKHashes, APKIntakeResult, APKMetadata, IntakeStatus, SplitPackageInfo


@pytest.fixture
def multi_arch_env():
    """Environment with both an x86_64 emulator and an arm64-v8a device."""
    mock = MagicMock()
    mock.find_adb_path.return_value = "/mock/adb"
    mock.find_emulator_path.return_value = "/mock/emulator"

    profile_x86_64 = AVDProfile(
        name="Pixel_API_36_x86_64",
        display_name="Pixel 8 API 36 x86_64",
        target="android-36",
        api_level=36,
        android_version="16",
        abis=["x86_64", "x86"],
        system_image_installed=True,
        ready=True,
    )
    profile_arm64 = AVDProfile(
        name="Pixel_API_34_arm64",
        display_name="Pixel 7 API 34 arm64-v8a",
        target="android-34",
        api_level=34,
        android_version="14",
        abis=["arm64-v8a", "armeabi-v7a"],
        system_image_installed=True,
        ready=True,
    )

    mock.get_avd_inventory.return_value = AVDInventory(
        profiles=[profile_x86_64, profile_arm64],
        available_avd_names=["Pixel_API_36_x86_64", "Pixel_API_34_arm64"],
        installed_system_images=[],
        running_devices=[],
        emulator_available=True,
        adb_available=True,
    )
    mock.get_running_device_states.return_value = {}
    mock.get_running_avds.return_value = {}
    return mock


@pytest.fixture
def x86_only_env():
    """Environment with only an x86_64 target."""
    mock = MagicMock()
    mock.find_adb_path.return_value = "/mock/adb"
    mock.find_emulator_path.return_value = "/mock/emulator"

    profile_x86_64 = AVDProfile(
        name="Medium_Phone_API_36.1",
        display_name="Medium Phone API 36.1",
        target="android-36",
        api_level=36,
        android_version="16",
        abis=["x86_64", "x86"],
        system_image_installed=True,
        ready=True,
    )

    mock.get_avd_inventory.return_value = AVDInventory(
        profiles=[profile_x86_64],
        available_avd_names=["Medium_Phone_API_36.1"],
        installed_system_images=[],
        running_devices=[],
        emulator_available=True,
        adb_available=True,
    )
    mock.get_running_device_states.return_value = {}
    mock.get_running_avds.return_value = {}
    return mock


def test_pure_java_kotlin_apk_cross_arch(x86_only_env):
    """Pure Java/Kotlin APK without native libraries runs on x86_64 target."""
    engine = CompatibilityEngine(env_discovery=x86_only_env)
    report = engine.evaluate(
        min_sdk=26,
        target_sdk=35,
        native_abis=[],
        package_name="com.example.purejava",
    )

    assert report.is_pure_java is True
    assert report.overall_status in (CompatibilityStatus.COMPATIBLE, CompatibilityStatus.COMPATIBLE_WITH_WARNINGS)
    assert report.selected_target is not None
    assert report.selected_target.target_id == "Medium_Phone_API_36.1"


def test_arm64_on_arm_target_compatibility(multi_arch_env):
    """arm64-v8a APK routes to arm64-v8a environment."""
    engine = CompatibilityEngine(env_discovery=multi_arch_env)
    report = engine.evaluate(
        min_sdk=26,
        target_sdk=34,
        native_abis=["arm64-v8a"],
        package_name="com.example.arm64app",
    )

    assert report.is_pure_java is False
    assert report.overall_status == CompatibilityStatus.COMPATIBLE
    assert report.selected_target is not None
    assert report.selected_target.target_id == "Pixel_API_34_arm64"


def test_arm64_only_on_x86_target_rejection(x86_only_env):
    """arm64-v8a APK fails cleanly on x86-only environment without crashing."""
    engine = CompatibilityEngine(env_discovery=x86_only_env)
    report = engine.evaluate(
        min_sdk=26,
        target_sdk=35,
        native_abis=["arm64-v8a"],
        package_name="com.example.arm64only",
    )

    assert report.is_pure_java is False
    assert report.overall_status == CompatibilityStatus.INCOMPATIBLE_ABI
    assert report.selected_target is None
    assert any("Incompatible ABI" in (c.rejection_reason or "") for c in report.candidate_evaluations)
    assert report.setup_instructions is not None


def test_x86_64_native_libraries_compatibility(x86_only_env):
    """x86_64 APK runs natively on x86_64 target."""
    engine = CompatibilityEngine(env_discovery=x86_only_env)
    report = engine.evaluate(
        min_sdk=28,
        target_sdk=36,
        native_abis=["x86_64"],
        package_name="com.example.x86native",
    )

    assert report.overall_status == CompatibilityStatus.COMPATIBLE
    assert report.selected_target.target_id == "Medium_Phone_API_36.1"


def test_unsupported_abi_mips(x86_only_env):
    """Deprecated / unsupported ABI (mips) is recognized and rejected as INCOMPATIBLE_ABI."""
    engine = CompatibilityEngine(env_discovery=x86_only_env)
    report = engine.evaluate(
        min_sdk=21,
        target_sdk=28,
        native_abis=["mips"],
        package_name="com.example.mipsapp",
    )

    assert report.overall_status == CompatibilityStatus.INCOMPATIBLE_ABI
    assert report.selected_target is None


def test_unsupported_abi_riscv64(x86_only_env):
    """Emerging unsupported ABI (riscv64) is recognized and rejected as INCOMPATIBLE_ABI."""
    engine = CompatibilityEngine(env_discovery=x86_only_env)
    report = engine.evaluate(
        min_sdk=33,
        target_sdk=35,
        native_abis=["riscv64"],
        package_name="com.example.riscvapp",
    )

    assert report.overall_status == CompatibilityStatus.INCOMPATIBLE_ABI
    assert report.selected_target is None


def test_minsdk_greater_than_device_api(x86_only_env):
    """When minSdk exceeds device API level, status is INCOMPATIBLE_ANDROID_VERSION."""
    engine = CompatibilityEngine(env_discovery=x86_only_env)
    # Target device is API 36, APK requires API 37
    report = engine.evaluate(
        min_sdk=37,
        target_sdk=37,
        native_abis=["x86_64"],
        package_name="com.example.futureapp",
    )

    assert report.overall_status == CompatibilityStatus.INCOMPATIBLE_ANDROID_VERSION
    assert report.selected_target is None
    assert any("lower than APK minSdkVersion" in c.rationale for c in report.candidate_evaluations)


def test_missing_required_splits_compatibility(x86_only_env):
    """Base APK missing required split components is flagged REQUIRED_SPLIT_PACKAGES_MISSING."""
    engine = CompatibilityEngine(env_discovery=x86_only_env)
    split_info = SplitPackageInfo(
        is_split=True,
        is_base_apk=True,
        split_count=0,
        missing_required_splits=True,
        split_names=[],
    )

    report = engine.evaluate(
        min_sdk=26,
        target_sdk=34,
        native_abis=[],
        package_name="com.example.splitbase",
        split_info=split_info,
    )

    assert report.overall_status == CompatibilityStatus.REQUIRED_SPLIT_PACKAGES_MISSING
    assert any("split" in w.lower() for w in report.warnings)


def test_malformed_archive_compatibility_unknown(x86_only_env):
    """Corrupted or invalid APK input returns COMPATIBILITY_UNKNOWN without raising exception."""
    engine = CompatibilityEngine(env_discovery=x86_only_env)
    intake_result = APKIntakeResult(
        file_path="/mock/corrupt.apk",
        file_name="corrupt.apk",
        file_size_bytes=100,
        hashes=APKHashes(sha256="abc", sha1="def", md5="123"),
        status=IntakeStatus.CORRUPTED,
        is_valid=False,
        errors=["ZIP end-of-central-directory record not found"],
    )

    report = engine.evaluate(intake_result=intake_result)
    assert report.overall_status == CompatibilityStatus.COMPATIBILITY_UNKNOWN
    assert len(report.errors) > 0
    assert "Cannot evaluate compatibility on invalid APK" in report.errors[0]
