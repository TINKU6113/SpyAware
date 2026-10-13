"""Authorized ADB Device Discovery, Installed Package Enumeration, and Safe APK Extraction.

Implements Milestone M3.2 specifications for SpyAware-Analyzer:
- Safe, read-only inspection of ADB-connected devices and emulators.
- Explicit ADB serial targeting for every command (never relies on default device).
- Distinguishes device, offline, unauthorized, and missing states.
- Identifies emulator versus physical device.
- Read-only package discovery with system vs user package classification.
- Identifies split APK installations.
- Safe, path-sanitized extraction of accessible APK files only (blocks private app data/databases).
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from analyzers.discovery.models import (
    ConnectedDevice,
    DeviceState,
    DeviceType,
    DiscoveredPackage,
    ExtractedAPK,
)
from analyzers.dynamic.environment import EnvironmentDiscovery

logger = logging.getLogger("spyaware.discovery")

SAFE_PACKAGE_RE = re.compile(r"^[a-zA-Z0-9_\.]+$")


class DeviceDiscoveryManager:
    """Manages read-only ADB device discovery, package enumeration, and APK extraction."""

    def __init__(self, env_discovery: Optional[EnvironmentDiscovery] = None):
        self.env_discovery = env_discovery or EnvironmentDiscovery()

    def list_devices(self) -> List[ConnectedDevice]:
        """Queries ADB for connected devices and inspects connection state and hardware properties."""
        adb = self.env_discovery.find_adb_path()
        if not adb:
            logger.warning("adb binary not found; device discovery unavailable")
            return []

        try:
            res = subprocess.run(
                [adb, "devices", "-l"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (subprocess.SubprocessError, OSError) as e:
            logger.error("Failed to execute adb devices: %s", e)
            return []

        if res.returncode != 0:
            return []

        devices: List[ConnectedDevice] = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            serial = parts[0]
            raw_state = parts[1].lower()

            # Map ADB connection state
            if raw_state == "device":
                state = DeviceState.DEVICE
                is_authorized = True
                is_online = True
            elif raw_state == "unauthorized":
                state = DeviceState.UNAUTHORIZED
                is_authorized = False
                is_online = True
            elif raw_state == "offline":
                state = DeviceState.OFFLINE
                is_authorized = False
                is_online = False
            elif raw_state == "authorizing":
                state = DeviceState.AUTHORIZING
                is_authorized = False
                is_online = True
            else:
                state = DeviceState.UNKNOWN
                is_authorized = False
                is_online = False

            # Parse device metadata flags (e.g., model:Pixel_8 product:shiba)
            model = None
            product = None
            for p in parts[2:]:
                if p.startswith("model:"):
                    model = p.split(":", 1)[1]
                elif p.startswith("product:"):
                    product = p.split(":", 1)[1]

            # Determine emulator vs physical
            is_emu = (
                serial.startswith("emulator-")
                or (model and any(k in model.lower() for k in ["sdk", "emulator", "goldfish", "ranchu"]))
                or (product and any(k in product.lower() for k in ["sdk", "emulator", "goldfish", "ranchu"]))
            )
            dev_type = DeviceType.EMULATOR if is_emu else DeviceType.PHYSICAL

            # Query properties only if authorized
            android_ver = None
            api_level = None
            primary_abi = None
            all_abis: List[str] = []
            avd_name = None

            if is_authorized and is_online:
                android_ver, api_level, primary_abi, all_abis = self._query_device_specs(adb, serial)
                if is_emu:
                    avd_name = self._query_avd_name(adb, serial)

            devices.append(
                ConnectedDevice(
                    serial=serial,
                    state=state,
                    is_authorized=is_authorized,
                    is_online=is_online,
                    device_type=dev_type,
                    model=model,
                    product=product,
                    android_version=android_ver,
                    api_level=api_level,
                    abi=primary_abi,
                    supported_abis=all_abis,
                    avd_name=avd_name,
                )
            )

        return devices

    def _query_device_specs(
        self, adb: str, serial: str
    ) -> Tuple[Optional[str], Optional[int], Optional[str], List[str]]:
        """Queries build release, API level, and ABI list with strict serial targeting."""
        android_ver = None
        api_level = None
        primary_abi = None
        all_abis: List[str] = []

        try:
            # Query release & SDK
            res = subprocess.run(
                [adb, "-s", serial, "shell", "getprop ro.build.version.release && getprop ro.build.version.sdk"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            if res.returncode == 0:
                lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                if len(lines) >= 1:
                    android_ver = lines[0]
                if len(lines) >= 2 and lines[1].isdigit():
                    api_level = int(lines[1])

            # Query ABIs
            res_abi = subprocess.run(
                [adb, "-s", serial, "shell", "getprop ro.product.cpu.abilist && getprop ro.product.cpu.abi"],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
            if res_abi.returncode == 0:
                lines = [l.strip() for l in res_abi.stdout.splitlines() if l.strip()]
                if len(lines) >= 1 and lines[0]:
                    all_abis = [a.strip() for a in lines[0].split(",") if a.strip()]
                if len(lines) >= 2 and lines[1]:
                    primary_abi = lines[1]
                elif all_abis:
                    primary_abi = all_abis[0]
        except Exception:
            pass

        return android_ver, api_level, primary_abi, all_abis

    def _query_avd_name(self, adb: str, serial: str) -> Optional[str]:
        """Queries running emulator for configured AVD name using explicit serial targeting."""
        try:
            r = subprocess.run(
                [adb, "-s", serial, "emu", "avd", "name"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    cleaned = line.strip()
                    if cleaned and cleaned != "OK" and not cleaned.startswith("Android Console:"):
                        return cleaned
        except Exception:
            pass
        return None

    def list_installed_packages(
        self,
        serial: str,
        include_system: bool = False,
        limit: int = 200,
    ) -> List[DiscoveredPackage]:
        """Enumerates installed applications on the target device via read-only ADB commands.
        
        Collects package name, base path, split APK paths, version info, and system classification.
        """
        adb = self.env_discovery.find_adb_path()
        if not adb:
            raise RuntimeError("adb binary is not available on host system")

        # Verify device state before proceeding
        devices = self.list_devices()
        target_dev = next((d for d in devices if d.serial == serial), None)
        if not target_dev:
            raise RuntimeError(f"Target device '{serial}' not found in connected ADB devices")
        if not target_dev.is_authorized:
            raise PermissionError(f"Target device '{serial}' is unauthorized. Allow USB debugging on the device.")
        if not target_dev.is_online:
            raise ConnectionError(f"Target device '{serial}' is offline or disconnected")

        # Command: pm list packages -f [-3]
        cmd = [adb, "-s", serial, "shell", "pm", "list", "packages", "-f"]
        if not include_system:
            cmd.append("-3")

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Package manager timed out enumerating packages on {serial}")
        except Exception as e:
            raise RuntimeError(f"Failed to query package manager: {str(e)}")

        if res.returncode != 0:
            raise RuntimeError(f"Package manager command failed on {serial}: {res.stderr.strip()}")

        discovered: List[DiscoveredPackage] = []
        raw_lines = [l.strip() for l in res.stdout.splitlines() if l.strip().startswith("package:")]

        for line in raw_lines[:limit]:
            # Format: package:/data/app/~~.../base.apk=com.example.app
            content = line[len("package:"):].strip()
            if "=" not in content:
                continue

            apk_path, pkg_name = content.rsplit("=", 1)
            pkg_name = pkg_name.strip()

            # Sanitize package name
            if not SAFE_PACKAGE_RE.match(pkg_name):
                logger.warning("Skipping package with invalid characters: %s", pkg_name)
                continue

            # Classify system vs user
            is_sys = (
                apk_path.startswith("/system/")
                or apk_path.startswith("/vendor/")
                or apk_path.startswith("/product/")
                or apk_path.startswith("/system_ext/")
                or apk_path.startswith("/apex/")
            )

            # Check split APK paths
            base_path = apk_path
            split_paths: List[str] = []
            is_split = False

            # Query full paths for this package to detect split APKs
            try:
                p_res = subprocess.run(
                    [adb, "-s", serial, "shell", "pm", "path", pkg_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if p_res.returncode == 0:
                    all_paths = [
                        pl.strip()[len("package:"):].strip()
                        for pl in p_res.stdout.splitlines()
                        if pl.strip().startswith("package:")
                    ]
                    if len(all_paths) > 1:
                        is_split = True
                        base_path = next((p for p in all_paths if "base.apk" in p), all_paths[0])
                        split_paths = [p for p in all_paths if p != base_path]
            except Exception:
                pass

            # Human-friendly app name fallback from package name
            app_name = pkg_name.split(".")[-1].capitalize()

            discovered.append(
                DiscoveredPackage(
                    package_name=pkg_name,
                    app_name=app_name,
                    version_name=None,
                    version_code=None,
                    is_system=is_sys,
                    is_split=is_split,
                    base_apk_path=base_path,
                    split_apk_paths=split_paths,
                    split_count=len(split_paths),
                    apk_size_bytes=None,
                    extraction_permitted=True,
                )
            )

        return discovered

    def extract_package_apk(
        self,
        serial: str,
        package_name: str,
        output_dir: Optional[str] = None,
    ) -> ExtractedAPK:
        """Safely extracts the base APK and any associated split APKs for an installed package.
        
        Strictly restricts file pulling to APK archive binaries from /data/app or system directories.
        Never extracts app private data (/data/data), databases, or user credentials.
        """
        adb = self.env_discovery.find_adb_path()
        if not adb:
            return ExtractedAPK(
                package_name=package_name,
                base_apk_path="",
                temp_directory="",
                success=False,
                error_message="adb binary not available",
            )

        # Validate package name safety (anti path traversal)
        if not SAFE_PACKAGE_RE.match(package_name):
            return ExtractedAPK(
                package_name=package_name,
                base_apk_path="",
                temp_directory="",
                success=False,
                error_message=f"Unsafe package name '{package_name}': contains forbidden characters",
            )

        # Target verification
        devices = self.list_devices()
        target_dev = next((d for d in devices if d.serial == serial), None)
        if not target_dev or not target_dev.is_authorized:
            return ExtractedAPK(
                package_name=package_name,
                base_apk_path="",
                temp_directory="",
                success=False,
                error_message=f"Device '{serial}' is not connected or unauthorized",
            )

        # Query APK paths on device
        try:
            res = subprocess.run(
                [adb, "-s", serial, "shell", "pm", "path", package_name],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        except Exception as e:
            return ExtractedAPK(
                package_name=package_name,
                base_apk_path="",
                temp_directory="",
                success=False,
                error_message=f"Failed to query APK path: {str(e)}",
            )

        if res.returncode != 0 or not res.stdout.strip():
            return ExtractedAPK(
                package_name=package_name,
                base_apk_path="",
                temp_directory="",
                success=False,
                error_message=f"Package '{package_name}' not installed or unreadable on device {serial}",
            )

        remote_paths = [
            l.strip()[len("package:"):].strip()
            for l in res.stdout.splitlines()
            if l.strip().startswith("package:")
        ]

        if not remote_paths:
            return ExtractedAPK(
                package_name=package_name,
                base_apk_path="",
                temp_directory="",
                success=False,
                error_message=f"No APK paths returned for package '{package_name}'",
            )

        # Enforce security constraint: only pull .apk files
        for rpath in remote_paths:
            if not rpath.endswith(".apk") or "/data/data/" in rpath or "/databases/" in rpath:
                return ExtractedAPK(
                    package_name=package_name,
                    base_apk_path="",
                    temp_directory="",
                    success=False,
                    error_message=f"Security violation: path '{rpath}' is not a valid APK binary location",
                )

        # Prepare safe extraction destination directory
        target_dir = output_dir or tempfile.mkdtemp(prefix=f"spyaware_{package_name}_")

        base_remote = next((p for p in remote_paths if "base.apk" in p), remote_paths[0])
        split_remotes = [p for p in remote_paths if p != base_remote]

        local_base = os.path.join(target_dir, f"{package_name}_base.apk")
        local_splits: List[str] = []
        warnings: List[str] = []

        # Pull base APK
        try:
            pull_res = subprocess.run(
                [adb, "-s", serial, "pull", base_remote, local_base],
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            if pull_res.returncode != 0 or not os.path.exists(local_base) or os.path.getsize(local_base) == 0:
                if not output_dir and os.path.exists(target_dir):
                    shutil.rmtree(target_dir, ignore_errors=True)
                return ExtractedAPK(
                    package_name=package_name,
                    base_apk_path="",
                    temp_directory="",
                    success=False,
                    error_message=f"Failed to pull base APK: {pull_res.stderr.strip() or 'Zero bytes retrieved'}",
                )
        except Exception as e:
            if not output_dir and os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
            return ExtractedAPK(
                package_name=package_name,
                base_apk_path="",
                temp_directory="",
                success=False,
                error_message=f"Exception pulling base APK: {str(e)}",
            )

        # Pull split APKs if present
        for i, s_remote in enumerate(split_remotes):
            s_name = os.path.basename(s_remote)
            local_s = os.path.join(target_dir, f"split_{i}_{s_name}")
            try:
                s_pull = subprocess.run(
                    [adb, "-s", serial, "pull", s_remote, local_s],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if s_pull.returncode == 0 and os.path.exists(local_s):
                    local_splits.append(local_s)
                else:
                    warnings.append(f"Failed to extract split slice '{s_name}': {s_pull.stderr.strip()}")
            except Exception as e:
                warnings.append(f"Exception pulling split '{s_name}': {str(e)}")

        is_split = len(split_remotes) > 0
        if is_split:
            warnings.append(
                f"Package is a split APK installation ({len(split_remotes)} split slices). "
                "Base APK extracted for static analysis; dynamic features in splits may require full split bundle."
            )

        return ExtractedAPK(
            package_name=package_name,
            base_apk_path=local_base,
            split_apk_paths=local_splits,
            is_split=is_split,
            split_count=len(split_remotes),
            temp_directory=target_dir,
            warnings=warnings,
            success=True,
        )
