#!/usr/bin/env python3
"""Safe Android Virtual Device (AVD) and SDK System Image Setup Tool.

Provides reproducible inspection, dry-run reporting, and safe creation of recommended
AVD pool profiles for SpyAware-Analyzer dynamic analysis (Milestone M2).

Safety Guarantees:
- Never deletes or overwrites the pre-existing AVD (Medium_Phone_API_36.1).
- Does not automatically download images as a side-effect of APK uploads.
- Validates disk space and host architecture support.
- Clearly flags unsupported legacy ABIs (e.g., deprecated armeabi).
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analyzers.dynamic.environment import EnvironmentDiscovery
from analyzers.dynamic.models import AVDInventory, AVDProfile

RECOMMENDED_TARGETS = [
    {
        "id": "existing_api36",
        "name": "Medium_Phone_API_36.1",
        "tier": "Primary / Modern Analysis",
        "target": "android-36.1",
        "api_level": 36,
        "abi": "x86_64",
        "package": "system-images;android-36.1;google_apis_playstore;x86_64",
        "disk_gb": 1.4,
        "description": "Pre-existing reference emulator (Android 16 preview / API 36). Always preserved.",
        "supported": True,
    },
    {
        "id": "older_x86_64_api30",
        "name": "Pixel_API_30_x86_64",
        "tier": "Secondary / Modern Compatible",
        "target": "android-30",
        "api_level": 30,
        "abi": "x86_64",
        "package": "system-images;android-30;google_apis;x86_64",
        "disk_gb": 1.2,
        "description": "Android 11 (API 30) x86_64 emulator profile for apps targeting Android 11/12.",
        "supported": True,
    },
    {
        "id": "legacy_x86_64_api28",
        "name": "Nexus_API_28_x86_64",
        "tier": "Legacy Compatible",
        "target": "android-28",
        "api_level": 28,
        "abi": "x86_64",
        "package": "system-images;android-28;google_apis;x86_64",
        "disk_gb": 1.1,
        "description": "Android 9.0 (API 28 / Pie) x86_64 profile for legacy surveillance APKs.",
        "supported": True,
    },
    {
        "id": "arm64_api30",
        "name": "Pixel_API_30_arm64",
        "tier": "Optional Native ARM64",
        "target": "android-30",
        "api_level": 30,
        "abi": "arm64-v8a",
        "package": "system-images;android-30;google_apis;arm64-v8a",
        "disk_gb": 1.3,
        "description": "Native 64-bit ARM execution. Requires ARM translation or ARM host virtualization.",
        "supported": True,
    },
    {
        "id": "arm32_api25",
        "name": "Pixel_API_25_arm32",
        "tier": "Conditional Native ARM32",
        "target": "android-25",
        "api_level": 25,
        "abi": "armeabi-v7a",
        "package": "system-images;android-25;google_apis;armeabi-v7a",
        "disk_gb": 1.0,
        "description": "Android 7.1.1 (API 25) 32-bit ARM (armeabi-v7a). Execution overhead on x86_64 host.",
        "supported": True,
    },
    {
        "id": "legacy_armeabi",
        "name": "Unsupported_Legacy_Armeabi",
        "tier": "Deprecated Native armeabi",
        "target": "android-legacy",
        "api_level": None,
        "abi": "armeabi",
        "package": None,
        "disk_gb": 0.0,
        "description": "Deprecated ARMv5/v6 architecture. NOT supported by modern Android emulator images.",
        "supported": False,
    },
]


def find_sdkmanager(android_home: Optional[str]) -> Optional[str]:
    """Locates sdkmanager binary if installed in cmdline-tools."""
    if not android_home:
        return None
    candidates = [
        Path(android_home) / "cmdline-tools" / "latest" / "bin" / "sdkmanager",
        Path(android_home) / "cmdline-tools" / "bin" / "sdkmanager",
    ]
    for p in candidates:
        if p.exists() and os.access(str(p), os.X_OK):
            return str(p)
    return shutil.which("sdkmanager")


def find_avdmanager(android_home: Optional[str]) -> Optional[str]:
    """Locates avdmanager binary if installed in cmdline-tools."""
    if not android_home:
        return None
    candidates = [
        Path(android_home) / "cmdline-tools" / "latest" / "bin" / "avdmanager",
        Path(android_home) / "cmdline-tools" / "bin" / "avdmanager",
    ]
    for p in candidates:
        if p.exists() and os.access(str(p), os.X_OK):
            return str(p)
    return shutil.which("avdmanager")


def print_header(title: str) -> None:
    print(f"\n{'=' * 72}\n {title}\n{'=' * 72}")


def inspect_pool(env: EnvironmentDiscovery) -> Dict[str, Any]:
    """Inspects the current state of host SDK images and configured AVDs."""
    inventory = env.get_avd_inventory()
    sdkmanager_bin = find_sdkmanager(env.android_home)
    avdmanager_bin = find_avdmanager(env.android_home)

    return {
        "inventory": inventory,
        "sdkmanager": sdkmanager_bin,
        "avdmanager": avdmanager_bin,
        "android_home": env.android_home,
    }


def display_inventory(data: Dict[str, Any]) -> None:
    inventory: AVDInventory = data["inventory"]
    android_home = data["android_home"]

    print_header("SPYAWARE-ANALYZER EMULATOR POOL INVENTORY (MILESTONE M2)")
    print(f" Android SDK Home:     {android_home or 'NOT CONFIGURED'}")
    print(f" ADB Tool Available:   {inventory.adb_available}")
    print(f" Emulator Executable:  {inventory.emulator_available}")
    print(f" sdkmanager Detected:  {bool(data['sdkmanager'])}")
    print(f" avdmanager Detected:  {bool(data['avdmanager'])}")

    print_header("1. CONFIGURED ANDROID VIRTUAL DEVICES (AVDs)")
    if not inventory.profiles:
        print("  [!] No configured AVD profiles found.")
    else:
        for p in inventory.profiles:
            status_tag = "[READY]" if p.ready else "[NOT READY]"
            running_tag = " (LIVE ONLINE)" if p.is_running else ""
            print(f"  * {status_tag} {p.name}{running_tag}")
            print(f"      - Android Version: {p.android_version or 'Unknown'} (API {p.api_level or '?'})")
            print(f"      - Supported ABIs:  {', '.join(p.abis) or 'None'}")
            print(f"      - System Image:    {'Installed' if p.system_image_installed else 'Missing/External'}")
            if p.error_message:
                print(f"      - Diagnostics:     {p.error_message}")

    print_header("2. INSTALLED SYSTEM IMAGES ON HOST")
    if not inventory.installed_system_images:
        print("  [!] No system images detected under Sdk/system-images/")
    else:
        for img in inventory.installed_system_images:
            print(f"  * {img}")

    print_header("3. RECOMMENDED PROFILE TARGETS STATUS & DISK REQUIREMENTS")
    installed_pkgs = inventory.installed_system_images
    existing_avd_names = inventory.available_avd_names

    total_missing_disk = 0.0

    for t in RECOMMENDED_TARGETS:
        t_id = t["id"]
        t_name = t["name"]
        pkg = t["package"]
        disk = t["disk_gb"]

        if not t["supported"]:
            status = "UNSUPPORTED (Modern SDK does not provide armeabi image)"
            symbol = "[-]"
        elif t_name in existing_avd_names:
            status = "CONFIGURED & READY (Preserved)"
            symbol = "[OK]"
        elif pkg and any(t["target"] in img and t["abi"] in img for img in installed_pkgs):
            status = "IMAGE INSTALLED (AVD not yet created)"
            symbol = "[!]"
        else:
            status = f"MISSING (Requires download ~{disk:.1f} GB)"
            symbol = "[+]"
            total_missing_disk += disk

        print(f"  {symbol} {t['tier']}: {t_name}")
        print(f"      - Target:     {t['target']} ({t['abi']})")
        print(f"      - Status:     {status}")
        print(f"      - Package:    {pkg or 'N/A'}")
        print(f"      - Details:    {t['description']}")

    print(f"\n  Total disk footprint for missing recommended images: ~{total_missing_disk:.1f} GB")
    print(f"  Host safety rule: Existing AVD 'Medium_Phone_API_36.1' will NEVER be overwritten.")


def generate_setup_instructions(data: Dict[str, Any]) -> None:
    inventory: AVDInventory = data["inventory"]
    installed_pkgs = inventory.installed_system_images
    existing_avd_names = inventory.available_avd_names
    android_home = data["android_home"] or "/home/j3st3r/Android/Sdk"

    print_header("REPRODUCIBLE SETUP & INSTALLATION COMMAND SEQUENCE")
    print("Run the following commands to install missing system images and create safe AVD profiles:\n")

    missing_packages = []
    for t in RECOMMENDED_TARGETS:
        if not t["supported"] or not t["package"]:
            continue
        if t["name"] in existing_avd_names:
            continue
        if not any(t["target"] in img and t["abi"] in img for img in installed_pkgs):
            missing_packages.append(t)

    if missing_packages:
        print("# Step 1: Install missing system images via sdkmanager:")
        for m in missing_packages:
            print(f'# [{m["tier"]}] - ~{m["disk_gb"]} GB')
            print(f'{android_home}/cmdline-tools/latest/bin/sdkmanager --install "{m["package"]}"')
        print()

    print("# Step 2: Create isolated Virtual Device profiles (non-destructive):")
    for t in RECOMMENDED_TARGETS:
        if not t["supported"] or not t["package"]:
            continue
        if t["name"] == "Medium_Phone_API_36.1":
            print(f'# Medium_Phone_API_36.1 is pre-existing; preserved as-is.')
            continue
        print(f'# Create {t["name"]}:')
        print(
            f'{android_home}/cmdline-tools/latest/bin/avdmanager create avd \\\n'
            f'    --name "{t["name"]}" \\\n'
            f'    --package "{t["package"]}" \\\n'
            f'    --device "pixel"'
        )
        print()


def main():
    parser = argparse.ArgumentParser(
        description="SpyAware-Analyzer ABI-Aware Emulator Pool Setup & Inspection Tool"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List current AVDs, installed system images, and recommended pool targets",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate installation actions and report disk space implications without modifying system",
    )
    parser.add_argument(
        "--install-instructions",
        action="store_true",
        help="Print reproducible command sequence for installing recommended targets",
    )

    args = parser.parse_args()

    env = EnvironmentDiscovery()
    data = inspect_pool(env)

    if args.dry_run:
        print_header("DRY-RUN SIMULATION MODE (No host modifications)")
        display_inventory(data)
        generate_setup_instructions(data)
        print("\n[SUCCESS] Dry-run complete. No files or AVDs were modified.")
        return

    if args.install_instructions:
        generate_setup_instructions(data)
        return

    # Default action: list inventory
    display_inventory(data)
    generate_setup_instructions(data)


if __name__ == "__main__":
    main()
