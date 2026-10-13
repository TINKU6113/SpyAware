"""Unit tests for ABI- and Android-Version-Aware Compatibility Engine (Milestone M3.1)."""

from unittest.mock import MagicMock, patch
import pytest

from analyzers.dynamic.compatibility import (
    CandidateEnvironmentEvaluation,
    CompatibilityEngine,
    CompatibilityReport,
    CompatibilityStatus,
)
from analyzers.dynamic.models import AVDInventory, AVDProfile
from analyzers.intake.models import APKIntakeResult, APKMetadata, IntakeStatus


@pytest.fixture
def mock_env_discovery():
    mock = MagicMock()
    mock.find_adb_path.return_value = "/mock/path/to/adb"
    mock.find_emulator_path.return_value = "/mock/path/to/emulator"

    # Default configured inventory: Medium_Phone_API_36.1 (x86_64, API 36)
    profile_36 = AVDProfile(
        name="Medium_Phone_API_36.1",
        display_name="Medium Phone API 36.1",
        target="android-36.1",
        api_level=36,
        android_version="16 (Baklava)",
        abis=["x86_64", "x86"],
        system_image_installed=True,
        ready=True,
    )
    mock.get_avd_inventory.return_value = AVDInventory(
        profiles=[profile_36],
        available_avd_names=["Medium_Phone_API_36.1"],
        installed_system_images=["system-images/android-36.1/google_apis_playstore/x86_64"],
        running_devices=[],
        emulator_available=True,
        adb_available=True,
    )
    mock.get_running_device_states.return_value = {}
    mock.get_running_avds.return_value = {}
    return mock


@pytest.fixture
def engine(mock_env_discovery):
    return CompatibilityEngine(env_discovery=mock_env_discovery)


def test_pure_java_apk_compatibility(engine):
    """Pure Java/Kotlin APKs run on any architecture."""
    report = engine.evaluate(
        min_sdk=26,
        target_sdk=34,
        native_abis=[],  # Pure Java
        package_name="com.example.purejava",
    )
    assert report.is_pure_java is True
    assert report.overall_status in (CompatibilityStatus.COMPATIBLE, CompatibilityStatus.COMPATIBLE_WITH_WARNINGS)
    assert report.selected_target is not None
    assert report.selected_target.target_id == "Medium_Phone_API_36.1"
    assert "Pure Java/Kotlin APK" in report.selected_target.rationale


def test_x86_64_native_apk_compatibility(engine):
    """APK with x86_64 libraries on x86_64 emulator is compatible."""
    report = engine.evaluate(
        min_sdk=28,
        target_sdk=34,
        native_abis=["x86_64"],
        package_name="com.example.x86native",
    )
    assert report.overall_status in (CompatibilityStatus.COMPATIBLE, CompatibilityStatus.COMPATIBLE_WITH_WARNINGS)
    assert report.selected_target is not None
    assert "x86_64" in report.selected_target.supported_abis


def test_incompatible_abi_rejection(engine):
    """APK with arm64-only native libraries on an x86_64-only emulator is rejected."""
    report = engine.evaluate(
        min_sdk=28,
        target_sdk=33,
        native_abis=["arm64-v8a"],
        package_name="com.example.armonly",
    )
    assert report.overall_status == CompatibilityStatus.INCOMPATIBLE_ABI
    assert report.selected_target is None
    assert report.setup_instructions is not None
    assert "arm64-v8a" in report.setup_instructions


def test_incompatible_legacy_armeabi_rejection(engine):
    """APK requiring deprecated armeabi (ARMv5) is rejected on modern emulators."""
    report = engine.evaluate(
        min_sdk=16,
        target_sdk=22,
        native_abis=["armeabi"],
        package_name="com.example.legacyarmeabi",
    )
    assert report.overall_status == CompatibilityStatus.INCOMPATIBLE_ABI
    assert report.selected_target is None


def test_multi_abi_apk_compatibility(engine):
    """APK with both arm64-v8a and x86_64 is compatible because x86_64 matches."""
    report = engine.evaluate(
        min_sdk=24,
        target_sdk=34,
        native_abis=["arm64-v8a", "x86_64"],
        package_name="com.example.fatbinary",
    )
    assert report.overall_status in (CompatibilityStatus.COMPATIBLE, CompatibilityStatus.COMPATIBLE_WITH_WARNINGS)
    assert report.selected_target is not None


def test_incompatible_android_version(engine, mock_env_discovery):
    """APK requiring minSdk 38 on API 36 emulator is rejected for version too old."""
    report = engine.evaluate(
        min_sdk=38,
        target_sdk=38,
        native_abis=[],
        package_name="com.example.futureapi",
    )
    assert report.overall_status == CompatibilityStatus.INCOMPATIBLE_ANDROID_VERSION
    assert report.selected_target is None
    assert any("Android version too old" in (c.rejection_reason or "") for c in report.candidate_evaluations)


def test_compatible_with_warnings_for_target_sdk_mismatch(engine, mock_env_discovery):
    """Target API lower than targetSdk produces COMPATIBLE_WITH_WARNINGS."""
    # Configure an API 28 emulator
    profile_28 = AVDProfile(
        name="Pixel_API_28",
        target="android-28",
        api_level=28,
        abis=["x86_64"],
        system_image_installed=True,
        ready=True,
    )
    mock_env_discovery.get_avd_inventory.return_value = AVDInventory(
        profiles=[profile_28],
        available_avd_names=["Pixel_API_28"],
        installed_system_images=["system-images/android-28/google_apis/x86_64"],
        emulator_available=True,
        adb_available=True,
    )

    report = engine.evaluate(
        min_sdk=24,
        target_sdk=34,  # minSdk 24 is compatible with API 28, but targetSdk 34 is higher
        native_abis=[],
        package_name="com.example.targetnewer",
    )
    assert report.overall_status == CompatibilityStatus.COMPATIBLE_WITH_WARNINGS
    assert report.selected_target is not None
    assert any("compatibility mode" in w for w in report.selected_target.warnings)


def test_running_device_ranked_higher_than_offline_avd(engine, mock_env_discovery):
    """A live running emulator gets higher rank score than an offline AVD."""
    mock_env_discovery.get_running_device_states.return_value = {"emulator-5554": "device"}
    mock_env_discovery.get_running_avds.return_value = {"Medium_Phone_API_36.1": "emulator-5554"}

    with patch.object(engine, "_query_device_properties", return_value=(36, ["x86_64", "x86"], True)):
        report = engine.evaluate(
            min_sdk=26,
            target_sdk=34,
            native_abis=[],
            package_name="com.example.runningtest",
        )
        assert report.selected_target is not None
        assert report.selected_target.is_running is True
        assert report.selected_target.target_type == "RUNNING_EMULATOR"
        assert report.selected_target.rank_score > 150


def test_compatibility_unknown_for_empty_metadata(engine):
    """Missing or corrupted metadata results in COMPATIBILITY_UNKNOWN."""
    report = engine.evaluate(
        min_sdk=None,
        target_sdk=None,
        native_abis=[],
        package_name=None,
    )
    assert report.overall_status == CompatibilityStatus.COMPATIBILITY_UNKNOWN


def test_required_capability_unavailable_when_no_avds(engine, mock_env_discovery):
    """When no AVDs or devices exist, report REQUIRED_CAPABILITY_UNAVAILABLE."""
    mock_env_discovery.get_avd_inventory.return_value = AVDInventory(
        profiles=[],
        available_avd_names=[],
        installed_system_images=[],
        running_devices=[],
        emulator_available=False,
        adb_available=True,
    )
    mock_env_discovery.get_running_device_states.return_value = {}

    report = engine.evaluate(
        min_sdk=26,
        target_sdk=34,
        native_abis=[],
        package_name="com.example.noenv",
    )
    assert report.overall_status == CompatibilityStatus.REQUIRED_CAPABILITY_UNAVAILABLE
    assert report.setup_instructions is not None
