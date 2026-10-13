"""Host Environment Discovery for Android Dynamic Analysis in SpyAware-Analyzer.

Discovers local adb, emulator, and avdmanager binaries, scans available AVDs,
inspects installed Android SDK system images, evaluates APK ABI & API compatibility,
and manages AVD profile inventories.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from analyzers.dynamic.models import AVDInventory, AVDProfile, EnvironmentStatus


class EnvironmentDiscovery:
    """Discovers and inspects the Android dynamic analysis host environment."""

    def __init__(self):
        self.android_home = (
            os.environ.get("ANDROID_HOME")
            or os.environ.get("ANDROID_SDK_ROOT")
            or str(Path.home() / "Android" / "Sdk")
        )

    def find_adb_path(self) -> Optional[str]:
        """Locates the adb binary on PATH or within Android SDK platform-tools."""
        which_path = shutil.which("adb")
        if which_path and os.path.exists(which_path):
            return which_path

        if self.android_home:
            candidate = os.path.join(self.android_home, "platform-tools", "adb")
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate

        return None

    def find_emulator_path(self) -> Optional[str]:
        """Locates the emulator binary on PATH or within Android SDK emulator directory."""
        which_path = shutil.which("emulator")
        if which_path and os.path.exists(which_path):
            return which_path

        if self.android_home:
            candidate = os.path.join(self.android_home, "emulator", "emulator")
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                return candidate

        return None

    def find_avdmanager_path(self) -> Optional[str]:
        """Locates the avdmanager binary on PATH or within Android SDK cmdline-tools."""
        which_path = shutil.which("avdmanager")
        if which_path and os.path.exists(which_path):
            return which_path

        if self.android_home:
            candidates = [
                os.path.join(self.android_home, "cmdline-tools", "latest", "bin", "avdmanager"),
                os.path.join(self.android_home, "tools", "bin", "avdmanager"),
            ]
            for candidate in candidates:
                if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                    return candidate

        return None

    def find_frida_path(self) -> Optional[str]:
        """Locates the frida binary on PATH if installed."""
        return shutil.which("frida")

    def list_available_avds(self, emulator_path: Optional[str] = None) -> List[str]:
        """Queries the emulator CLI and filesystem to list configured AVD images."""
        avds: List[str] = []

        # 1. Query emulator CLI if available
        emu = emulator_path or self.find_emulator_path()
        if emu:
            try:
                res = subprocess.run(
                    [emu, "-list-avds"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        name = line.strip()
                        if name and name not in avds:
                            avds.append(name)
            except (subprocess.SubprocessError, OSError):
                pass

        # 2. Inspect ~/.android/avd directory as a resilient fallback
        try:
            avd_dir = Path.home() / ".android" / "avd"
            if avd_dir.exists() and avd_dir.is_dir():
                for ini_file in avd_dir.glob("*.ini"):
                    avd_name = ini_file.stem
                    if avd_name and avd_name not in avds:
                        avds.append(avd_name)
        except OSError:
            pass

        return sorted(avds)

    def discover_installed_system_images(self) -> List[str]:
        """Scans Android SDK directory to identify all locally installed system images."""
        installed: List[str] = []
        if not self.android_home:
            return installed

        sys_img_base = Path(self.android_home) / "system-images"
        if not sys_img_base.exists() or not sys_img_base.is_dir():
            return installed

        try:
            for prop_file in sys_img_base.glob("*/*/*/source.properties"):
                rel_path = str(prop_file.parent.relative_to(Path(self.android_home)))
                if rel_path not in installed:
                    installed.append(rel_path)
        except OSError:
            pass

        return sorted(installed)

    def inspect_avd_profile(self, avd_name: str) -> AVDProfile:
        """Inspects AVD configuration files (.ini, config.ini, source.properties) to construct profile."""
        if not avd_name:
            return AVDProfile(name="", ready=False, error_message="Empty AVD name")

        avd_dir = Path.home() / ".android" / "avd"
        ini_file = avd_dir / f"{avd_name}.ini"
        avd_config_path = None
        target_str = "unknown"

        if ini_file.exists():
            try:
                with open(ini_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("path="):
                            avd_config_path = Path(line.split("=", 1)[1].strip())
                        elif line.startswith("target="):
                            target_str = line.split("=", 1)[1].strip()
            except OSError:
                pass

        if not avd_config_path:
            candidate = avd_dir / f"{avd_name}.avd"
            if candidate.exists():
                avd_config_path = candidate

        display_name = avd_name
        abi_type = None
        hw_cpu = None
        image_sysdir = ""
        api_level = None
        android_version = None

        if avd_config_path and avd_config_path.exists():
            config_ini = avd_config_path / "config.ini"
            if config_ini.exists():
                try:
                    with open(config_ini, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("avd.ini.displayname="):
                                display_name = line.split("=", 1)[1].strip()
                            elif line.startswith("abi.type="):
                                abi_type = line.split("=", 1)[1].strip()
                            elif line.startswith("hw.cpu.arch="):
                                hw_cpu = line.split("=", 1)[1].strip()
                            elif line.startswith("image.sysdir"):
                                image_sysdir = line.split("=", 1)[1].strip()
                            elif line.startswith("target="):
                                target_str = line.split("=", 1)[1].strip()
                except OSError:
                    pass

        # Parse API level from target string (e.g. android-36.1 -> 36, android-30 -> 30)
        target_match = re.search(r"android-(\d+)", target_str, re.IGNORECASE)
        if target_match:
            try:
                api_level = int(target_match.group(1))
            except ValueError:
                pass

        if not api_level and image_sysdir:
            sys_match = re.search(r"android-(\d+)", image_sysdir, re.IGNORECASE)
            if sys_match:
                try:
                    api_level = int(sys_match.group(1))
                except ValueError:
                    pass

        # Check system image existence
        sys_image_installed = False
        if image_sysdir and self.android_home:
            full_sys_dir = Path(self.android_home) / image_sysdir
            if full_sys_dir.exists():
                sys_image_installed = True
                source_prop = full_sys_dir / "source.properties"
                if source_prop.exists():
                    try:
                        with open(source_prop, "r", encoding="utf-8", errors="ignore") as spf:
                            for sline in spf:
                                sline = sline.strip()
                                if sline.startswith("AndroidVersion.ApiLevel="):
                                    val = sline.split("=", 1)[1].strip()
                                    try:
                                        api_level = int(float(val))
                                    except ValueError:
                                        pass
                                elif sline.startswith("SystemImage.Abi="):
                                    abi_type = sline.split("=", 1)[1].strip()
                    except OSError:
                        pass

        # Map API level to human-readable Android version
        api_to_version = {
            36: "16 (Baklava)",
            35: "15 (Vanilla Ice Cream)",
            34: "14 (Upside Down Cake)",
            33: "13 (Tiramisu)",
            32: "12L",
            31: "12",
            30: "11",
            29: "10",
            28: "9.0 (Pie)",
            27: "8.1 (Oreo)",
            26: "8.0 (Oreo)",
            25: "7.1 (Nougat)",
            24: "7.0 (Nougat)",
            23: "6.0 (Marshmallow)",
            22: "5.1 (Lollipop)",
            21: "5.0 (Lollipop)",
        }
        if api_level:
            android_version = api_to_version.get(api_level, f"API {api_level}")

        # Resolve supported ABIs strictly without false assertions
        base_abi = abi_type or hw_cpu
        abis: List[str] = []
        if base_abi:
            if base_abi == "x86_64":
                # Modern x86_64 images support x86_64 and 32-bit x86
                abis = ["x86_64", "x86"]
            elif base_abi == "x86":
                abis = ["x86"]
            elif base_abi in ("arm64-v8a", "arm64"):
                # ARM64 supports arm64-v8a and armeabi-v7a (NOT deprecated armeabi unless proven)
                abis = ["arm64-v8a", "armeabi-v7a"]
            elif base_abi in ("armeabi-v7a", "arm"):
                abis = ["armeabi-v7a"]
            elif base_abi == "armeabi":
                # Deprecated legacy armeabi is distinct
                abis = ["armeabi"]
            else:
                abis = [base_abi]

        # Name-based heuristic fallback only if config could not be parsed
        if not abis and avd_name:
            low = avd_name.lower()
            if "arm64" in low:
                abis = ["arm64-v8a", "armeabi-v7a"]
            elif "armeabi-v7a" in low or "arm32" in low:
                abis = ["armeabi-v7a"]
            elif "armeabi" in low:
                abis = ["armeabi"]
            elif "x86_64" in low:
                abis = ["x86_64", "x86"]
            elif "x86" in low:
                abis = ["x86"]

        emu_available = self.find_emulator_path() is not None
        ready = bool(avd_config_path and avd_config_path.exists() and emu_available)
        error_msg = None
        if not emu_available:
            ready = False
            error_msg = "emulator binary not found"
        elif not sys_image_installed and image_sysdir:
            # Note: sys_image_installed may be False if SDK path differs, but check if config exists
            pass

        return AVDProfile(
            name=avd_name,
            display_name=display_name,
            target=target_str,
            api_level=api_level,
            android_version=android_version,
            abis=abis,
            system_image_dir=image_sysdir or None,
            system_image_installed=sys_image_installed,
            ready=ready,
            error_message=error_msg,
        )

    def get_avd_supported_abis(self, avd_name: str) -> List[str]:
        """Inspects AVD configuration files to determine supported CPU architectures."""
        if not avd_name:
            return []
        profile = self.inspect_avd_profile(avd_name)
        return profile.abis

    def find_compatible_avd(
        self, required_abis: List[str], available_avds: Optional[List[str]] = None
    ) -> Optional[str]:
        """Searches available AVDs for one supporting at least one of the required ABIs."""
        if not required_abis:
            return None
        avds = available_avds if available_avds is not None else self.list_available_avds()
        for avd in avds:
            supported = self.get_avd_supported_abis(avd)
            if any(abi in supported for abi in required_abis):
                return avd
        return None

    def evaluate_apk_compatibility(
        self,
        avd: AVDProfile,
        apk_min_sdk: Optional[int] = None,
        apk_abis: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """Evaluates whether an AVD profile is compatible with an APK's API and ABI requirements.
        
        Returns (is_compatible, reason_or_failure_classification).
        """
        # 1. Check Android API level compatibility
        if apk_min_sdk is not None and avd.api_level is not None:
            if avd.api_level < apk_min_sdk:
                return (
                    False,
                    f"INCOMPATIBLE_ANDROID_VERSION: APK minSdk ({apk_min_sdk}) "
                    f"exceeds AVD API level ({avd.api_level})",
                )

        # 2. Check native CPU architecture compatibility
        req_abis = apk_abis or []
        if not req_abis:
            # Pure Java / Kotlin APK: compatible with any AVD
            return (
                True,
                "Compatible: Pure Java/Kotlin APK without native libraries runs on any architecture",
            )

        # Legacy armeabi verification: do not falsely claim support from modern images
        if "armeabi" in req_abis and "armeabi" not in avd.abis:
            # Deprecated armeabi is NOT armeabi-v7a
            if len(req_abis) == 1:
                return (
                    False,
                    "INCOMPATIBLE_ABI: APK requires deprecated armeabi architecture "
                    f"which is not supported by AVD '{avd.name}' (supports {avd.abis})",
                )

        matched = [a for a in req_abis if a in avd.abis]
        if matched:
            return (
                True,
                f"Compatible: Target AVD supports native architecture(s) {', '.join(matched)}",
            )

        return (
            False,
            f"INCOMPATIBLE_ABI: APK native architectures {req_abis} are not supported "
            f"by AVD '{avd.name}' (supports {avd.abis})",
        )

    def rank_compatible_avds(
        self,
        apk_min_sdk: Optional[int] = None,
        apk_target_sdk: Optional[int] = None,
        apk_abis: Optional[List[str]] = None,
        preferred_avd: Optional[str] = None,
    ) -> List[Tuple[AVDProfile, str]]:
        """Discovers, validates, and ranks all available AVD profiles compatible with the target APK.
        
        Returns ranked list of (AVDProfile, match_reason) tuples.
        """
        available_names = self.list_available_avds()
        profiles = [self.inspect_avd_profile(name) for name in available_names]
        running_devices = self.list_running_devices()

        compatible_candidates: List[Tuple[AVDProfile, str, int]] = []

        for p in profiles:
            is_compat, reason = self.evaluate_apk_compatibility(
                p, apk_min_sdk=apk_min_sdk, apk_abis=apk_abis
            )
            if not is_compat:
                continue

            # Compute rank score (higher = better)
            score = 0

            # Bonus for preferred configured AVD
            if preferred_avd and p.name == preferred_avd:
                score += 100
            elif p.name == "Medium_Phone_API_36.1":
                score += 50

            # Bonus for ready state
            if p.ready:
                score += 30

            # Proximity to targetSdk if known
            if apk_target_sdk and p.api_level:
                diff = abs(p.api_level - apk_target_sdk)
                score += max(0, 20 - diff)

            compatible_candidates.append((p, reason, score))

        # Sort descending by score
        compatible_candidates.sort(key=lambda c: c[2], reverse=True)
        return [(c[0], c[1]) for c in compatible_candidates]

    def get_avd_inventory(self) -> AVDInventory:
        """Returns complete inventory of configured AVD profiles and installed system images."""
        available_names = self.list_available_avds()
        profiles = [self.inspect_avd_profile(name) for name in available_names]
        installed_images = self.discover_installed_system_images()
        running_devices = self.list_running_devices()
        adb_path = self.find_adb_path()
        emu_path = self.find_emulator_path()

        # Update running state on profiles
        running_avds = self.get_running_avds(adb_path)
        for p in profiles:
            if running_avds:
                p.is_running = (p.name in running_avds)
            elif running_devices:
                p.is_running = any(d.startswith("emulator-") for d in running_devices)

        # Standard recommended pool targets (per Milestone M2 specifications)
        recommended_targets = [
            {
                "id": "existing_api36",
                "name": "Medium_Phone_API_36.1",
                "tier": "Modern Analysis (Android 16 preview / API 36)",
                "target": "android-36.1",
                "api_level": 36,
                "abi": "x86_64",
                "package": "system-images;android-36.1;google_apis_playstore;x86_64",
                "status": "INSTALLED" if any("android-36.1" in img and "x86_64" in img for img in installed_images) else "CONFIGURED",
                "disk_estimate_gb": 1.4,
            },
            {
                "id": "older_x86_64",
                "name": "Pixel_API_30",
                "tier": "Older x86_64 (Android 11 / API 30)",
                "target": "android-30",
                "api_level": 30,
                "abi": "x86_64",
                "package": "system-images;android-30;google_apis;x86_64",
                "status": "INSTALLED" if any("android-30" in img and "x86_64" in img for img in installed_images) else "NOT_INSTALLED",
                "disk_estimate_gb": 1.4,
            },
            {
                "id": "legacy_x86_64",
                "name": "Pixel_API_28",
                "tier": "Legacy x86_64 (Android 9.0 / API 28)",
                "target": "android-28",
                "api_level": 28,
                "abi": "x86_64",
                "package": "system-images;android-28;google_apis;x86_64",
                "status": "INSTALLED" if any("android-28" in img and "x86_64" in img for img in installed_images) else "NOT_INSTALLED",
                "disk_estimate_gb": 1.1,
            },
            {
                "id": "arm64",
                "name": "Pixel_ARM64_API_30",
                "tier": "ARM64 Profile (Android 11 / API 30)",
                "target": "android-30",
                "api_level": 30,
                "abi": "arm64-v8a",
                "package": "system-images;android-30;google_apis;arm64-v8a",
                "status": "INSTALLED" if any("android-30" in img and "arm64" in img for img in installed_images) else "NOT_INSTALLED",
                "disk_estimate_gb": 1.5,
                "note": "Optional; requires ARM translation or hardware emulation.",
            },
            {
                "id": "arm32",
                "name": "Nexus_ARM32_API_25",
                "tier": "ARM 32-bit Profile (Android 7.1 / API 25)",
                "target": "android-25",
                "api_level": 25,
                "abi": "armeabi-v7a",
                "package": "system-images;android-25;google_apis;armeabi-v7a",
                "status": "INSTALLED" if any("android-25" in img and "armeabi-v7a" in img for img in installed_images) else "NOT_INSTALLED",
                "disk_estimate_gb": 1.0,
                "note": "Conditional on genuinely usable emulator image/environment.",
            },
            {
                "id": "legacy_armeabi",
                "name": "Legacy_armeabi_Unsupported",
                "tier": "Legacy armeabi (Deprecated ARMv5/v6)",
                "target": "android-16",
                "api_level": 16,
                "abi": "armeabi",
                "package": "unavailable",
                "status": "UNSUPPORTED",
                "disk_estimate_gb": 0.0,
                "note": "Deprecated armeabi is distinct from armeabi-v7a and unsupported on modern emulator hosts.",
            },
        ]

        return AVDInventory(
            profiles=profiles,
            installed_system_images=installed_images,
            available_avd_names=available_names,
            running_devices=running_devices,
            emulator_available=emu_path is not None,
            adb_available=adb_path is not None,
            recommended_targets=recommended_targets,
        )

    def list_running_devices(self, adb_path: Optional[str] = None) -> List[str]:
        """Queries adb for currently connected devices or running emulators."""
        devices: List[str] = []
        adb = adb_path or self.find_adb_path()
        if not adb:
            return devices

        try:
            res = subprocess.run(
                [adb, "devices"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("List of devices"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] == "device":
                        devices.append(parts[0])
        except (subprocess.SubprocessError, OSError):
            pass

        return devices

    def get_running_device_states(self, adb_path: Optional[str] = None) -> Dict[str, str]:
        """Queries adb for connected devices and their connection states."""
        adb = adb_path or self.find_adb_path()
        if not adb:
            return {}
        states: Dict[str, str] = {}
        try:
            res = subprocess.run(
                [adb, "devices"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("List of devices"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        states[parts[0]] = parts[1]
                    elif len(parts) == 1:
                        states[parts[0]] = "unknown"
        except (subprocess.SubprocessError, OSError):
            pass
        return states

    def get_running_avds(self, adb_path: Optional[str] = None) -> Dict[str, str]:
        """Discovers running emulators and maps their configured AVD names to ADB serials."""
        adb = adb_path or self.find_adb_path()
        if not adb:
            return {}
        avd_map: Dict[str, str] = {}
        device_states = self.get_running_device_states(adb)
        for serial in device_states:
            if serial.startswith("emulator-"):
                avd_name = None
                # Primary: adb emu avd name
                try:
                    res = subprocess.run(
                        [adb, "-s", serial, "emu", "avd", "name"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        for line in res.stdout.splitlines():
                            cleaned = line.strip()
                            if cleaned and cleaned != "OK" and not cleaned.startswith("Android Console:"):
                                avd_name = cleaned
                                break
                except (subprocess.SubprocessError, OSError):
                    pass

                if not avd_name:
                    # Secondary: getprop
                    for prop in ["ro.boot.qemu.avd_name", "ro.kernel.qemu.avd_name"]:
                        try:
                            r = subprocess.run(
                                [adb, "-s", serial, "shell", "getprop", prop],
                                capture_output=True,
                                text=True,
                                timeout=5,
                                check=False,
                            )
                            if r.returncode == 0 and r.stdout.strip():
                                avd_name = r.stdout.strip()
                                break
                        except (subprocess.SubprocessError, OSError):
                            pass

                if avd_name:
                    avd_map[avd_name] = serial

        return avd_map

    def get_status(self) -> EnvironmentStatus:
        """Evaluates host environment readiness for dynamic analysis."""
        adb_path = self.find_adb_path()
        emu_path = self.find_emulator_path()
        avd_path = self.find_avdmanager_path()
        frida_path = self.find_frida_path()

        adb_available = adb_path is not None
        emulator_available = emu_path is not None
        avdmanager_available = avd_path is not None
        frida_available = frida_path is not None

        available_avds = self.list_available_avds(emu_path)
        running_devices = self.list_running_devices(adb_path)

        # Check configured AVD via environment variable
        configured_avd = os.environ.get("SPYAWARE_AVD_NAME")
        selected_avd = None

        if configured_avd:
            if configured_avd in available_avds:
                selected_avd = configured_avd
            else:
                selected_avd = configured_avd
        elif available_avds:
            selected_avd = available_avds[0]

        ready = adb_available and (bool(running_devices) or (emulator_available and bool(selected_avd)))

        if ready:
            if running_devices:
                message = f"Dynamic environment ready: Active device detected ({', '.join(running_devices)})"
            else:
                message = f"Dynamic environment ready: AVD '{selected_avd}' available for execution"
        else:
            missing = []
            if not adb_available:
                missing.append("adb")
            if not emulator_available:
                missing.append("emulator")
            if not available_avds and not running_devices:
                missing.append("configured AVD image")
            message = f"Dynamic environment not ready: Missing {', '.join(missing) if missing else 'required components'}"

        return EnvironmentStatus(
            adb_available=adb_available,
            emulator_available=emulator_available,
            avdmanager_available=avdmanager_available,
            frida_available=frida_available,
            available_avds=available_avds,
            running_devices=running_devices,
            selected_avd=selected_avd,
            ready=ready,
            message=message,
        )
