#!/usr/bin/env python3
"""Dataset Inventory and Deterministic Sample Selection for SpyAware-Analyzer.

Inventories the CIC Riskware dataset directory:
- Recursively discovers APK files.
- Validates archive integrity via UniversalAPKIntake.
- Extracts SHA-256, SHA-1, MD5, package metadata, permissions, ABIs.
- Detects duplicate APKs by SHA-256.
- Selects a diverse, representative subset of 15 unique valid APKs deterministically.
- Records all excluded samples and exclusion reasons.
- Outputs machine-readable JSON manifests under OUTPUT_DIR/inventory/.
"""

import argparse
import hashlib
import json
import logging
import os
import random
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from analyzers.intake.validator import UniversalAPKIntake
from analyzers.intake.models import APKIntakeResult, IntakeStatus

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("inventory")


def process_single_apk(file_path_str: str, dataset_dir_str: str) -> Dict[str, Any]:
    """Processes a single APK file, extracting metadata and archive status."""
    p = Path(file_path_str)
    dataset_dir = Path(dataset_dir_str)
    rel_path = str(p.relative_to(dataset_dir))
    
    intake = UniversalAPKIntake()
    result: APKIntakeResult = intake.validate_and_intake(file_path_str)
    
    sha256 = result.hashes.sha256 if result.hashes else ""
    if not sha256:
        # Fallback manual hash calculation if intake failed before hashing
        h = hashlib.sha256()
        with open(file_path_str, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        sha256 = h.hexdigest()

    meta = result.metadata
    return {
        "filename": p.name,
        "relative_source_path": rel_path,
        "file_size_bytes": result.file_size_bytes,
        "sha256": sha256,
        "sha1": result.hashes.sha1 if result.hashes else "",
        "md5": result.hashes.md5 if result.hashes else "",
        "is_valid_archive": result.is_valid,
        "intake_status": result.status.value,
        "package_name": meta.package_name if meta else None,
        "app_name": meta.app_name if meta else None,
        "version_name": meta.version_name if meta else None,
        "version_code": meta.version_code if meta else None,
        "min_sdk": meta.min_sdk if meta else None,
        "target_sdk": meta.target_sdk if meta else None,
        "declared_permissions": meta.permissions if meta else [],
        "declared_permission_count": len(meta.permissions) if meta else 0,
        "native_abis": result.native_abis,
        "has_native_libraries": result.has_native_libraries,
        "framework": result.framework.framework.value if result.framework else "UNKNOWN",
        "intake_errors": result.errors,
        "intake_warnings": result.warnings,
    }


def inventory_dataset(
    dataset_dir: Path,
    max_workers: int = 8,
) -> List[Dict[str, Any]]:
    """Inventories all APK files in dataset directory using multiprocessing."""
    apk_paths = sorted(list(dataset_dir.rglob("*.apk")))
    logger.info("Discovered %d APK files in %s", len(apk_paths), dataset_dir)
    
    items: List[Dict[str, Any]] = []
    t0 = time.time()
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(process_single_apk, str(p), str(dataset_dir)): p
            for p in apk_paths
        }
        done_count = 0
        total = len(apk_paths)
        for fut in as_completed(futures):
            done_count += 1
            if done_count % 500 == 0 or done_count == total:
                elapsed = time.time() - t0
                rate = done_count / elapsed if elapsed > 0 else 0
                logger.info("Processed %d/%d APKs (%.1f APKs/sec)...", done_count, total, rate)
            try:
                item = fut.result()
                items.append(item)
            except Exception as e:
                p = futures[fut]
                logger.error("Failed to process APK %s: %s", p.name, e)
                # Compute SHA256 fallback
                h = hashlib.sha256()
                try:
                    with open(p, "rb") as f:
                        while chunk := f.read(65536):
                            h.update(chunk)
                    digest = h.hexdigest()
                except Exception:
                    digest = ""
                items.append({
                    "filename": p.name,
                    "relative_source_path": str(p.relative_to(dataset_dir)),
                    "file_size_bytes": p.stat().st_size if p.exists() else 0,
                    "sha256": digest,
                    "sha1": "",
                    "md5": "",
                    "is_valid_archive": False,
                    "intake_status": "FAILED",
                    "package_name": None,
                    "app_name": None,
                    "version_name": None,
                    "version_code": None,
                    "min_sdk": None,
                    "target_sdk": None,
                    "declared_permissions": [],
                    "declared_permission_count": 0,
                    "native_abis": [],
                    "has_native_libraries": False,
                    "framework": "UNKNOWN",
                    "intake_errors": [str(e)],
                    "intake_warnings": [],
                })
                
    # Sort deterministically by SHA-256 then filename
    items.sort(key=lambda x: (x["sha256"], x["filename"]))
    logger.info("Inventory complete in %.2f seconds.", time.time() - t0)
    return items


def select_diverse_samples(
    inventory: List[Dict[str, Any]],
    target_count: int = 15,
    seed: int = 42,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Selects target_count diverse valid unique APKs deterministically.
    
    Identifies duplicates by SHA-256, marks exclusions with explicit reasons,
    and returns (selected_samples, excluded_samples).
    """
    seen_hashes: Set[str] = set()
    valid_unique: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []

    for item in inventory:
        sha = item["sha256"]
        if not item["is_valid_archive"] or item["intake_status"] != "VALID":
            item["is_duplicate"] = False
            item["inventory_status"] = "EXCLUDED"
            err = "; ".join(item["intake_errors"]) if item["intake_errors"] else item["intake_status"]
            item["exclusion_reason"] = f"Corrupted or invalid APK archive: {err}"
            excluded.append(item)
        elif sha in seen_hashes:
            item["is_duplicate"] = True
            item["inventory_status"] = "EXCLUDED"
            item["exclusion_reason"] = f"Duplicate content (SHA-256 collision: {sha})"
            excluded.append(item)
        else:
            seen_hashes.add(sha)
            item["is_duplicate"] = False
            valid_unique.append(item)

    logger.info(
        "Inventory breakdown: Total=%d, Valid Unique=%d, Corrupted/Invalid=%d, Duplicates=%d",
        len(inventory),
        len(valid_unique),
        sum(1 for e in excluded if "Corrupted" in e["exclusion_reason"]),
        sum(1 for e in excluded if "Duplicate" in e["exclusion_reason"]),
    )

    if len(valid_unique) <= target_count:
        for it in valid_unique:
            it["inventory_status"] = "SELECTED"
            it["exclusion_reason"] = None
        return valid_unique, excluded

    # Deterministic stratified selection across key surveillance and architectural diversity dimensions
    # Feature classification helpers
    def has_perm(it: Dict[str, Any], keyword: str) -> bool:
        return any(keyword in p.upper() for p in it["declared_permissions"])

    def is_surveillance_sms(it: Dict[str, Any]) -> bool:
        return has_perm(it, "SMS") or has_perm(it, "CALL_LOG") or has_perm(it, "READ_PHONE_STATE")

    def is_surveillance_media(it: Dict[str, Any]) -> bool:
        return has_perm(it, "CAMERA") or has_perm(it, "RECORD_AUDIO")

    def is_surveillance_location(it: Dict[str, Any]) -> bool:
        return has_perm(it, "ACCESS_FINE_LOCATION") or has_perm(it, "ACCESS_COARSE_LOCATION")

    def is_overlay_accessibility(it: Dict[str, Any]) -> bool:
        return has_perm(it, "SYSTEM_ALERT_WINDOW") or has_perm(it, "ACCESSIBILITY")

    # Define 15 targeted diversity profiles
    criteria = [
        # 1. Pure Java: SMS / Telephony surveillance
        ("Pure Java - SMS / Telephony Interception",
         lambda it: not it["has_native_libraries"] and is_surveillance_sms(it) and (it.get("target_sdk") or 0) <= 22),
        
        # 2. Pure Java: Media surveillance (Camera / Audio recording)
        ("Pure Java - Audio / Video Sensor Capture",
         lambda it: not it["has_native_libraries"] and is_surveillance_media(it)),

        # 3. Pure Java: Geolocation tracking
        ("Pure Java - Precision Geolocation Tracking",
         lambda it: not it["has_native_libraries"] and is_surveillance_location(it)),

        # 4. Pure Java: Overlay / Tapjacking permission
        ("Pure Java - Overlay Window Capability",
         lambda it: not it["has_native_libraries"] and is_overlay_accessibility(it)),

        # 5. Pure Java: High permission footprint (> 15 permissions)
        ("Pure Java - Extensive Permission Footprint",
         lambda it: not it["has_native_libraries"] and it["declared_permission_count"] >= 15),

        # 6. Pure Java: Minimal permission footprint (1 to 5 permissions)
        ("Pure Java - Minimal Permission Footprint",
         lambda it: not it["has_native_libraries"] and 1 <= it["declared_permission_count"] <= 5),

        # 7. Pure Java: Legacy API compatibility (targetSdk <= 19)
        ("Pure Java - Legacy Android Platform Target",
         lambda it: not it["has_native_libraries"] and (it.get("target_sdk") or 0) <= 19 and (it.get("target_sdk") or 0) > 0),

        # 8. Pure Java: Modern runtime permissions (targetSdk >= 23)
        ("Pure Java - Runtime Permission Architecture",
         lambda it: not it["has_native_libraries"] and (it.get("target_sdk") or 0) >= 23),

        # 9. Native ABI: armeabi with SMS or Telephony
        ("Native armeabi - Telephony Surveillance",
         lambda it: "armeabi" in it["native_abis"] and is_surveillance_sms(it)),

        # 10. Native ABI: armeabi-v7a with Geolocation or Media
        ("Native armeabi-v7a - Sensor / Geolocation",
         lambda it: "armeabi-v7a" in it["native_abis"] and (is_surveillance_location(it) or is_surveillance_media(it))),

        # 11. Native ABI: Multi-ABI packaging (e.g. armeabi + x86 or v7a + x86)
        ("Native Multi-ABI - Cross-Architecture Support",
         lambda it: len(it["native_abis"]) >= 2 and any("x86" in abi for abi in it["native_abis"])),

        # 12. Native ABI: 64-bit or arm64 / x86_64 compatible
        ("Native Architecture - Secondary ABI Support",
         lambda it: it["has_native_libraries"] and any(abi in ("arm64-v8a", "x86", "x86_64") for abi in it["native_abis"])),

        # 13. Native ABI: Large package (> 5 MB)
        ("Native Libraries - Large Application Package",
         lambda it: it["has_native_libraries"] and it["file_size_bytes"] >= 5 * 1024 * 1024),

        # 14. Pure Java: Compact utility (< 500 KB)
        ("Pure Java - Lightweight Package Footprint",
         lambda it: not it["has_native_libraries"] and it["file_size_bytes"] <= 500 * 1024),

        # 15. General Riskware: Balanced multi-sensor profile
        ("General Riskware - Multi-Vector Sensor & Telephony",
         lambda it: (is_surveillance_sms(it) or is_surveillance_media(it)) and is_surveillance_location(it)),
    ]

    selected: List[Dict[str, Any]] = []
    selected_shas: Set[str] = set()

    # Deterministic candidate selection: sort pool by SHA-256
    pool_sorted = sorted(valid_unique, key=lambda x: x["sha256"])

    for profile_name, predicate in criteria:
        if len(selected) >= target_count:
            break
        candidate = None
        for item in pool_sorted:
            if item["sha256"] in selected_shas:
                continue
            if predicate(item):
                candidate = item
                break
        if candidate:
            candidate["selection_stratum"] = profile_name
            selected.append(candidate)
            selected_shas.add(candidate["sha256"])
            logger.info("Selected [%02d/%02d] %s: %s (SHA256: %s...)",
                        len(selected), target_count, profile_name, candidate["filename"], candidate["sha256"][:12])

    # Fill any remaining slots deterministically from unselected pool
    if len(selected) < target_count:
        logger.info("Filling remaining %d slots from unselected pool...", target_count - len(selected))
        for item in pool_sorted:
            if len(selected) >= target_count:
                break
            if item["sha256"] not in selected_shas:
                item["selection_stratum"] = "Deterministic Pool Fill"
                selected.append(item)
                selected_shas.add(item["sha256"])

    # Mark inventory statuses
    for item in valid_unique:
        if item["sha256"] in selected_shas:
            item["inventory_status"] = "SELECTED"
            item["exclusion_reason"] = None
        else:
            item["inventory_status"] = "EXCLUDED"
            item["exclusion_reason"] = f"Excluded: Exceeded representative evaluation target size ({target_count} samples)"
            excluded.append(item)

    # Sort selected deterministically by SHA-256
    selected.sort(key=lambda x: x["sha256"])
    excluded.sort(key=lambda x: (x["sha256"], x["filename"]))

    logger.info("Selection finalized: %d SELECTED, %d EXCLUDED", len(selected), len(excluded))
    return selected, excluded


def main():
    parser = argparse.ArgumentParser(description="Dataset Inventory and Sample Selection")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("/home/j3st3r/Desktop/SpyAware-Report-Preparation/Riskware(1)/Riskware"),
        help="Path to dataset directory",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/home/j3st3r/Desktop/SpyAware-Report-Preparation/SpyAware-CIC-Evaluation"),
        help="Path to evaluation output directory",
    )
    parser.add_argument(
        "--sample-count",
        type=int,
        default=15,
        help="Target number of unique valid samples to select (default: 15)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic selection seed (default: 42)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of parallel worker processes (default: 8)",
    )

    args = parser.parse_args()

    inventory_dir = args.output_dir / "inventory"
    inventory_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Starting dataset inventory...")
    inventory = inventory_dataset(args.dataset_dir, max_workers=args.workers)

    logger.info("Executing deterministic sample selection...")
    selected, excluded = select_diverse_samples(
        inventory, target_count=args.sample_count, seed=args.seed
    )

    # Save outputs
    inventory_path = inventory_dir / "dataset_inventory.json"
    selected_path = inventory_dir / "selected_samples.json"
    excluded_path = inventory_dir / "excluded_samples.json"

    logger.info("Writing dataset_inventory.json (%d items)...", len(inventory))
    with open(inventory_path, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)

    logger.info("Writing selected_samples.json (%d items)...", len(selected))
    with open(selected_path, "w", encoding="utf-8") as f:
        json.dump(selected, f, indent=2)

    logger.info("Writing excluded_samples.json (%d items)...", len(excluded))
    with open(excluded_path, "w", encoding="utf-8") as f:
        json.dump(excluded, f, indent=2)

    print("\n" + "=" * 80)
    print(" DATASET INVENTORY AND SAMPLE SELECTION SUMMARY")
    print("=" * 80)
    print(f"Total Discovered Files: {len(inventory)}")
    print(f"Unique Valid APKs:     {len(selected) + len([e for e in excluded if 'Exceeded' in (e.get('exclusion_reason') or '')])}")
    print(f"Selected Samples:      {len(selected)}")
    print(f"Excluded Samples:      {len(excluded)}")
    print(f"  - Corrupt/Invalid:   {sum(1 for e in excluded if 'Corrupted' in (e.get('exclusion_reason') or ''))}")
    print(f"  - Duplicates:        {sum(1 for e in excluded if 'Duplicate' in (e.get('exclusion_reason') or ''))}")
    print(f"  - Exceeded Cap:      {sum(1 for e in excluded if 'Exceeded' in (e.get('exclusion_reason') or ''))}")
    print("-" * 80)
    print(f"{'#':<3} {'SHA256 (PREFIX)':<18} {'PACKAGE NAME':<32} {'SIZE (KB)':<10} {'NATIVE ABIs':<15} {'STRATUM'}")
    print("-" * 80)
    for idx, s in enumerate(selected, 1):
        pkg = (s.get("package_name") or "unknown")[:30]
        size_kb = round(s["file_size_bytes"] / 1024, 1)
        abis = ",".join(s["native_abis"]) if s["native_abis"] else "pure-java"
        stratum = s.get("selection_stratum", "")[:28]
        print(f"{idx:<3} {s['sha256'][:16]:<18} {pkg:<32} {size_kb:<10} {abis:<15} {stratum}")
    print("=" * 80)
    print(f"Inventory saved to: {inventory_dir}")


if __name__ == "__main__":
    main()
