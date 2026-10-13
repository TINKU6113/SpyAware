# Milestone M3 Autonomous Implementation Report: Universal Android APK Security Analysis Platform

**Project:** SpyAware Analyzer (`~/AndroidStudioProjects/SpyAware-Analyzer`)  
**Mission:** Milestone M3 — Universal Android APK Security Analysis Platform  
**Execution Mode:** Fully Autonomous Engineering Session  
**Date:** October 11, 2026  
**Status:** COMPLETED & VERIFIED  

---

## 1. Executive Summary

During this autonomous engineering session, SpyAware Analyzer was substantially upgraded from an emulator-bound prototype into a **Universal Android APK Security Analysis Platform (Milestone M3)**. The platform now features:

1. **Centralized Universal Intake & Archive Sanitization Engine** (`analyzers/intake/`): Robust ZIP archive inspection with decompression ratio enforcement, traversal guards, cryptographic hashing (SHA-256, SHA-1, MD5), multi-framework identification (Flutter, React Native, Unity, Java/Kotlin), native ABI detection, and split-package layout analysis.
2. **ABI- & Android-Version-Aware Compatibility Engine** (`analyzers/dynamic/compatibility.py`): Deterministic target evaluation comparing APK minSdk/targetSdk and native ABIs against host environments, distinguishing pure Java/Kotlin vs single/multi-ABI vs legacy armeabi, and computing deterministic ranking scores with setup instructions.
3. **ADB Device Discovery & Safe Package Extraction** (`analyzers/discovery/`): Non-destructive enumeration of physical devices and emulators, read-only discovery of installed third-party and system packages, and secure sandboxed extraction of base/split APKs via explicit ADB serial targeting (`-s <serial>`).
4. **Enhanced Static Bytecode & Manifest Inspection** (`analyzers/static/`): Enriched `Finding` model with `rule_id`, confidence scores, remediation guidance, and evidence source; added static detection for reflection, runtime command execution, device admin abuse, ECB cipher misuse, hardcoded credentials with automatic secret redaction, and dangerous native library imports (`system`, `popen`, `ptrace`).
5. **Multi-Module Evidence Correlation & Confidence Scoring** (`risk_engine/`): Ground-truth correlation matrix distinguishing `CONFIRMED_ACTIVE_SURVEILLANCE`, `POTENTIAL_CAPABILITY_DORMANT`, `UNDOCUMENTED_RUNTIME_ACTIVITY`, and `INCOMPLETE_DYNAMIC_EVALUATION`, alongside analysis coverage percentages and Bayesian confidence metrics.
6. **Unified REST API Endpoints & Markdown Reporting** (`backend/api/router.py`): Exposed `/api/devices`, `/api/devices/{serial}/packages`, `/api/devices/{serial}/packages/{pkg}/analyze`, `/api/compatibility/check`, and `/api/analysis/{analysis_id}/export/markdown`.
7. **Frontend Modernization & Desktop ADB Integration** (`frontend/src/`): Connected desktop browser mode directly to backend ADB discovery, rendered intake cryptographic fingerprints, framework badges, and native ABIs, provided single-click Markdown report export, and displayed enriched finding cards with rule IDs, confidence percentages, and remediation advice.

All existing unit tests and architectures were preserved without regression. Across the platform, **268 backend tests passed (0 failed)** and **24 frontend tests passed (0 failed)**, with the frontend production Vite build compiling cleanly.

---

## 2. Baseline State Discovered

At the beginning of this autonomous session, the repository contained:
- **FastAPI Backend:** Static analysis (`analyzers/static/analyzer.py`), permission analysis (`analyzers/permissions/`), dynamic execution worker (`analyzers/dynamic/worker.py`), network socket analysis (`analyzers/network/worker.py`), and multi-module risk scoring (`risk_engine/engine.py`).
- **Test Baseline:** 225 backend unit tests passing in virtual environment (`./venv/bin/pytest`), 21 frontend unit tests passing in Node.js test runner (`npm test`).
- **Hardware/SDK Environment:** Ubuntu Linux with KVM hardware acceleration enabled (`/dev/kvm`), Android SDK at `~/Android/Sdk`, pre-configured AVD `Medium_Phone_API_36.1` (Android API 36, x86_64).
- **Synthetic Test Samples:** `samples/benign_sample.apk` (`com.spyaware.benign`), `samples/suspicious_surveillance_sample.apk`, `samples/critical_stalkerware_sample.apk`, `samples/network_positive_sample.apk`.
- **Identified Gaps:**
  - Lack of centralized intake: APK uploads were parsed ad-hoc, without zip-bomb limits or path traversal guards.
  - No ABI compatibility engine: pure Java APKs risked rejection if no native libraries were present, and arm64 APKs failed abruptly on x86 emulators.
  - No ADB device package extraction: desktop browser mode blocked package analysis with an "Android Wrapper Required" dialog.
  - Basic findings schema: lacked rule identifiers, remediation, confidence ratings, and secret redaction.
  - No evidence correlation: static capabilities and dynamic observations were scored independently without synergy attribution.
  - Missing human-readable Markdown export format.

---

## 3. Existing Capabilities Reused

The implementation deliberately built upon and preserved existing working components:
1. **Dynamic Execution Worker & Pool (`analyzers/dynamic/worker.py`, `runner.py`)**: Reused sequential emulator pool fallback, AVD locking (`AVDLock`), port reservation (5554-5584), and boot synchronization.
2. **Dynamic Observer (`analyzers/dynamic/observer.py`)**: Reused the 10 canonical surveillance categories (`CAMERA`, `MICROPHONE`, `LOCATION`, `ACCESSIBILITY`, `MEDIA_PROJECTION`, `SMS`, `CALL`, `BACKGROUND_SERVICE`, `PERSISTENCE`, `PROCESS`).
3. **Network Socket Telemetry (`analyzers/network/`)**: Reused kernel socket tracking via `/proc/net/tcp` and UID attribution.
4. **FastAPI Framework & Lifespan Architecture (`backend/main.py`, `backend/api/router.py`)**: Reused request routing, file streaming, and dependency injection patterns.
5. **Risk Engine Core (`risk_engine/engine.py`)**: Reused non-linear bounded score saturation and category-specific surveillance weighting.

---

## 4. New Capabilities Implemented

### Capability 1: Centralized Universal APK Intake & Archive Validation
- **Classification:** `IMPLEMENTED_AND_TESTED`
- **Location:** `analyzers/intake/models.py`, `analyzers/intake/validator.py`
- **Highlights:**
  - Enforces configurable archive boundaries: max size (150 MB), max entries (25,000), max uncompressed size (600 MB), max compression ratio (100:1).
  - Validates `PK\x03\x04` header and sanitizes all archive paths to prevent path traversal (`../`) and absolute path writes.
  - Calculates SHA-256, SHA-1, and MD5 hashes simultaneously during streamed ingestion.
  - Detects native ABIs from `lib/<abi>/` directories (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`, `riscv64`).
  - Detects application frameworks: Flutter (`libflutter.so`), React Native (`libreactnativejni.so`), Unity (`libunity.so`), Java/Kotlin DEX.
  - Detects common packers and dynamic code loaders: DexGuard, SecShell, Bangcle, Tencent Legu, Qihoo 360, `InMemoryDexClassLoader`.

### Capability 2: ABI- & Android-Version-Aware Compatibility Engine
- **Classification:** `IMPLEMENTED_AND_TESTED`
- **Location:** `analyzers/dynamic/compatibility.py`
- **Highlights:**
  - Evaluates compatibility status: `COMPATIBLE`, `INCOMPATIBLE_ABI`, `INCOMPATIBLE_ANDROID_VERSION`, `SPLIT_PACKAGE_REQUIRED`, `COMPATIBILITY_UNKNOWN`.
  - Accurately classifies pure Java/Kotlin applications (`is_pure_java=True`), permitting execution on any architecture without requiring native libraries.
  - Ranks candidate environments using deterministic scoring (running booted devices prioritized over stopped AVDs; matching ABIs prioritized; API level proximity scored).
  - Distinguishes legacy `armeabi` from `armeabi-v7a`.
  - Generates copy-paste CLI instructions (`avdmanager create avd`, `sdkmanager`) when no compatible environment is available.

### Capability 3: Installed-Application Discovery & Safe Package Extraction
- **Classification:** `IMPLEMENTED_AND_TESTED`
- **Location:** `analyzers/discovery/models.py`, `analyzers/discovery/manager.py`
- **Highlights:**
  - Enumerates connected physical devices and emulators via `adb devices -l`.
  - Queries device properties (`ro.build.version.release`, `ro.build.version.sdk`, `ro.product.cpu.abilist`).
  - Lists third-party (`pm list packages -3 -f`) and system packages without touching private data (`/data/data/`).
  - Safely extracts base APKs and split APK configurations (`split_config.*.apk`) to secure temporary scratch directories.
  - Enforces explicit ADB serial targeting (`-s <serial>`) to prevent multi-device race conditions.

### Capability 4: Deep Bytecode & Static Analysis Enhancements
- **Classification:** `IMPLEMENTED_AND_TESTED`
- **Location:** `analyzers/static/analyzer.py`, `backend/models/analysis.py`
- **Highlights:**
  - Enriched `Finding` model: added `finding_id`, `rule_id`, `confidence`, `evidence_source`, `remediation`, `security_impact`, and `false_positive_notes`.
  - Added new static inspection rules:
    - `STATIC_DEX_REFLECTION`: Java reflection and dynamic class loading invocation.
    - `STATIC_DEX_RUNTIME_EXEC`: Command execution via `Runtime.getRuntime().exec` or `ProcessBuilder`.
    - `STATIC_DEX_DEVICE_ADMIN`: Device admin receiver declarations for remote wipe/lock.
    - `STATIC_INSECURE_CRYPTO_ECB`: Insecure ECB mode symmetric cipher usage.
    - `STATIC_SECRET_HARDCODED_KEY`: Hardcoded API keys, private keys, or tokens.
    - `STATIC_NATIVE_DANGEROUS_IMPORTS`: ELF symbol scanning for `system`, `popen`, `ptrace`.
    - `STATIC_MANIFEST_BACKUP_ENABLED`: Unprotected `android:allowBackup="true"`.
  - Automated secret redaction: all hardcoded keys and tokens matching AWS, Google, or PKCS patterns are redacted (`[REDACTED]`) before report generation.
  - Finding deduplication: filters duplicate findings sharing the same rule and evidence.

### Capability 5: Risk Evidence Correlation & Bounded Multi-Module Engine
- **Classification:** `IMPLEMENTED_AND_TESTED`
- **Location:** `risk_engine/engine.py`
- **Highlights:**
  - Correlates static surveillance capabilities against runtime dynamic observations across 10 functional domains.
  - Assigns explicit correlation status:
    - `CONFIRMED_ACTIVE_SURVEILLANCE`: Static capability observed operating at runtime.
    - `POTENTIAL_CAPABILITY_DORMANT`: Static capability declared/present in DEX but inactive at runtime.
    - `UNDOCUMENTED_RUNTIME_ACTIVITY`: Dynamic activity observed without static manifest declaration.
    - `INCOMPLETE_DYNAMIC_EVALUATION`: Static capability present but dynamic sandbox skipped or unavailable.
  - Computes analysis coverage percentage (`coverage_percent`) and evidence-backed confidence scores (`confidence_score`).

### Capability 6: REST API Routing & Markdown Reporting
- **Classification:** `IMPLEMENTED_AND_TESTED`
- **Location:** `backend/api/router.py`, `backend/services/analysis_service.py`
- **Highlights:**
  - Added endpoints:
    - `GET /api/devices`: List authorized ADB devices with architecture and state.
    - `GET /api/devices/{serial}/packages`: Enumerate installed packages on target device.
    - `POST /api/devices/{serial}/packages/{package_name}/analyze`: Safely extract and run multi-module analysis.
    - `POST /api/compatibility/check`: Evaluate uploaded APK against host AVD inventory.
    - `GET /api/analysis/{analysis_id}/export/markdown`: Export full human-readable Markdown security audit.

### Capability 7: Frontend Desktop Discovery & Findings Visualization
- **Classification:** `IMPLEMENTED_AND_TESTED`
- **Location:** `frontend/src/App.tsx`, `frontend/src/types.ts`, `frontend/tests/`
- **Highlights:**
  - Removed desktop browser mode limitation: user can discover and analyze installed applications on connected emulators and devices.
  - Rendered intake cryptographic fingerprints (SHA-256), framework badges, native ABIs, and analysis coverage indicators.
  - Added single-click "Export Report (Markdown)" download alongside existing JSON export.
  - Updated finding cards with rule identifiers (`rule_id`), percentage confidence indicators, and green remediation blocks.

---

## 5. Exact Files Changed

### New Files Created
- `analyzers/intake/__init__.py`: Package initialization.
- `analyzers/intake/models.py`: Pydantic models for intake result, framework indicators, packing detection, and cryptographic hashes.
- `analyzers/intake/validator.py`: `UniversalAPKIntake` implementation with zip-bomb protection and framework parsers.
- `analyzers/dynamic/compatibility.py`: `CompatibilityEngine` and `CompatibilityReport` implementation.
- `analyzers/discovery/__init__.py`: Package initialization.
- `analyzers/discovery/models.py`: Pydantic models for ADB devices, packages, and extracted APKs.
- `analyzers/discovery/manager.py`: `DeviceDiscoveryManager` implementation.
- `tests/test_m3_intake.py`: 13 intake and validation regression tests.
- `tests/test_m3_compatibility.py`: 10 ABI/API compatibility regression tests.
- `tests/test_m3_discovery.py`: 8 device discovery and extraction regression tests.
- `tests/test_m3_static.py`: 6 static inspection and secret redaction regression tests.
- `tests/test_m3_api.py`: 6 REST API endpoint integration tests.
- `docs/M3_AUTONOMOUS_IMPLEMENTATION_REPORT.md`: This implementation report.

### Existing Files Modified
- `backend/models/analysis.py`: Added enriched fields to `Finding`, added intake fields to `StaticAnalysisResult` and `RiskReport`.
- `analyzers/static/analyzer.py`: Integrated `UniversalAPKIntake`, new static detection rules, symbol scanning, secret redaction, and deduplication.
- `risk_engine/engine.py`: Added `calculate_coverage`, `calculate_confidence`, `correlate_evidence`, and integrated correlation into risk calculation.
- `backend/services/analysis_service.py`: Added device discovery, installed package analysis, compatibility check, and Markdown report generation methods.
- `backend/api/router.py`: Registered new endpoints for devices, packages, compatibility check, and Markdown export.
- `frontend/src/types.ts`: Synchronized TypeScript interfaces (`Finding`, `StaticAnalysisResult`, `RiskReport`, `ConnectedDevice`, `DiscoveredPackage`).
- `frontend/src/App.tsx`: Added desktop ADB discovery fallback, Markdown export button, and enriched findings presentation.
- `frontend/tests/app_selection.test.ts`: Added unit tests for ADB package mapping, confidence formatting, and export URLs.

---

## 6. New API Endpoints and Schemas

| Method | Endpoint | Query / Body Params | Response Schema | Description |
|---|---|---|---|---|
| `GET` | `/api/devices` | None | `List[ConnectedDevice]` | Enumerate connected ADB devices with status, API level, and ABIs |
| `GET` | `/api/devices/{serial}/packages` | `include_system: bool = False` | `List[DiscoveredPackage]` | Enumerate installed applications on target authorized device |
| `POST` | `/api/devices/{serial}/packages/{pkg}/analyze` | `dynamic: bool`, `network: bool`, `avd: Optional[str]` | `RiskReport` | Safely pull APK from device and execute full analysis pipeline |
| `POST` | `/api/compatibility/check` | Multipart `file: UploadFile`, `avd: Optional[str]` | `CompatibilityReport` | Evaluate APK execution compatibility against host AVD inventory |
| `GET` | `/api/analysis/{analysis_id}/export/markdown` | None | `text/markdown` | Download comprehensive human-readable Markdown analysis report |

---

## 7. Frontend Changes

1. **Desktop ADB Discovery Mode:**
   - When `window.SpyAwareBridge` is absent, clicking "Select Installed App" queries `/api/devices` and retrieves the list of packages from the connected device or emulator.
   - If no devices are online, renders a descriptive setup guide and "Detect Connected Devices" retry button.
2. **Metadata Card Display:**
   - Cryptographic Fingerprint (SHA-256) block with one-click selection.
   - Framework & Runtime badge (e.g. `JAVA_KOTLIN`, `FLUTTER`, `REACT_NATIVE`, `UNITY`).
   - Native ABIs display (`Pure Java / No Native ABI` or detected architecture list).
   - Analysis Coverage & Bayesian Confidence score indicators.
3. **Enriched Findings View:**
   - Badge for rule identifier (`STATIC_DEX_REFLECTION`, `STATIC_SECRET_HARDCODED_KEY`, etc.).
   - Confidence percentage badge (e.g., `(95% confidence)`).
   - Evidence audit block with source attribution.
   - Green remediation action recommendations (`Remediation: ...`).
4. **Export Options:**
   - Added `Export Report (Markdown)` button triggering direct browser file download alongside JSON export.

---

## 8. Security Improvements

1. **ZIP Bomb & Resource Exhaustion Defense:** Rejects archives exceeding 150 MB compressed, 600 MB uncompressed, 25,000 files, or 100:1 compression ratio before memory allocation.
2. **Path Traversal Protection:** Validates every archive entry path to ensure entries cannot write to arbitrary directories outside scratch targets.
3. **Automated Secret Redaction:** Regex patterns identify AWS access keys, Google API keys, and PKCS private keys in code or assets and redact them (`[REDACTED]`) before inclusion in findings or reports.
4. **Safe ADB Command Execution:** Replaces string-interpolated shell commands with strict subprocess argument arrays (`["adb", "-s", serial, "shell", ...]`) and execution timeouts.
5. **Non-Destructive Package Pulling:** Only accesses public APK paths (`pm path`) in `/data/app/`. Never attempts to read private app data in `/data/data/`.
6. **Path Sanitization:** File uploads and serial paths are sanitized using `os.path.basename` to prevent path traversal on API endpoints.

---

## 9. Backend Test Results

- **Command Executed:** `./venv/bin/pytest tests/ -q`
- **Working Directory:** `~/AndroidStudioProjects/SpyAware-Analyzer`
- **Exit Status:** `0` (Success)
- **Results:**
  - **Total Tests:** 268 passed, 0 failed, 1 warning (Starlette deprecation warning).
  - **Execution Time:** 32.85 seconds.
  - **Breakdown of M3-Specific Test Suites:**
    - `tests/test_m3_intake.py`: 13 passed (Archive validation, hashes, ABIs, frameworks, packers, zip bombs).
    - `tests/test_m3_compatibility.py`: 10 passed (Pure Java, x86_64, arm64, minSdk, ranking, setup guidance).
    - `tests/test_m3_discovery.py`: 8 passed (Device listing, package discovery, split APK extraction, error handling).
    - `tests/test_m3_static.py`: 6 passed (Secret redaction, reflection detection, native symbol scanning, deduplication).
    - `tests/test_m3_api.py`: 6 passed (Devices endpoint, packages endpoint, compatibility check, Markdown export).
    - Previous Regression Suites: 225 passed (No regressions introduced).

---

## 10. Frontend Test Results

- **Command Executed:** `npm test -- --watchAll=false`
- **Working Directory:** `~/AndroidStudioProjects/SpyAware-Analyzer/frontend`
- **Exit Status:** `0` (Success)
- **Results:**
  - **Total Tests:** 24 passed, 0 failed across 7 test suites.
  - **Execution Time:** 209.6 ms.
  - **Test Suites Executed:**
    1. Frontend APK Selection & Validation (3 tests passed)
    2. Installed Application Discovery & Filtering (6 tests passed)
    3. Desktop Browser Fallback & Native Bridge Integration (3 tests passed)
    4. Frontend API URL Resolution & 150MB Limit (2 tests passed)
    5. Milestone M3 Desktop ADB Integration & Metadata Formatting (3 tests passed)
    6. Module Status Badging and Categorization (5 tests passed)
    7. Score Formatting & Progress Bar Defense (2 tests passed)

---

## 11. Production Build Results

- **Command Executed:** `npm run build`
- **Working Directory:** `~/AndroidStudioProjects/SpyAware-Analyzer/frontend`
- **Exit Status:** `0` (Success)
- **Build Output:**
  ```text
  > frontend@0.0.0 build
  > tsc -b && vite build

  vite v8.3.4 building client environment for production...
  ✓ 1899 modules transformed.
  rendering chunks (1)...computing gzip size...
  dist/index.html                   2.85 kB │ gzip:  0.92 kB
  dist/assets/index-DIDpEmuB.css   42.16 kB │ gzip:  7.99 kB
  dist/assets/index-B0JlAEll.js   352.92 kB │ gzip: 94.40 kB
  ✓ built in 590ms
  ```

---

## 12. Live Emulator & Pipeline Validation Results

Live evaluation of the full analysis pipeline was executed against synthetic samples:

### Live Evaluation: `samples/benign_sample.apk`
- **Package Name:** `com.spyaware.benign`
- **SHA-256:** `7574203d84bb80a97c985afc433476bbb1caf7f61680105998b725006e85b19a`
- **SHA-1:** `977f6b95b7781b0a8894df646dd3d41f71a9a8be`
- **MD5:** `52c03cf8075f7ee0e94bb713e89a5e1e`
- **Framework Detected:** `JAVA_KOTLIN`
- **Native ABIs:** `[]` (`Pure Java / Kotlin`)
- **Compatibility Status:** `COMPATIBLE` (Compatible with host AVD `Medium_Phone_API_36.1`, rank score 156)
- **Overall Score:** `16.8 / 100` (Classified: `LOW` Risk)
- **Analysis Status:** `COMPLETED_WITH_FINDINGS`
- **Coverage:** `50.0%` | **Confidence:** `0.50`
- **Key Findings (4 Total):**
  1. `[MEDIUM]` Application Signed with Debug Certificate (`STATIC_APPLICATION_SIGNED_WITH_DEBUG_`) (+10.0 pts)
  2. `[MEDIUM]` Exported Components Without Permission (`STATIC_EXPORTED_COMPONENTS_WITHOUT_PE`) (+8.0 pts)
  3. `[LOW]` Application Backup Enabled (`STATIC_MANIFEST_BACKUP_ENABLED`) (+2.0 pts)
  4. `[LOW]` Network & Internet Access (`INTERNET`) (+4.0 pts)

### Preset Samples Baseline Verification
- `samples/critical_stalkerware_sample.apk`: Score `100.0` (`CRITICAL`), SHA-256 `aced38f9470b848a2b83c37db87aa05296adadeab3edb113aa336706f1170516`.
- `samples/suspicious_surveillance_sample.apk`: Score `95.4` (`CRITICAL`), SHA-256 `b34718fd281230440b00c88bb2fa6d92031732adcff32df732c4d67d89859e48`.
- `samples/network_positive_sample.apk`: Score `24.8` (`LOW`), SHA-256 `3656b42c97839a9ec3881602dadf0eb20ba4f0bc4877caa1f58719142e662f86`.

---

## 13. APK Hash and Package Details for Live Validation

| Sample File | Package Name | SHA-256 Cryptographic Hash | Detected Framework | Native ABIs | Verified Risk Level |
|---|---|---|---|---|---|
| `benign_sample.apk` | `com.spyaware.benign` | `7574203d84bb80a97c985afc433476bbb1caf7f61680105998b725006e85b19a` | `JAVA_KOTLIN` | None (Pure Java) | `LOW` (16.8 pts) |
| `critical_stalkerware_sample.apk` | `com.covert.stalker` | `aced38f9470b848a2b83c37db87aa05296adadeab3edb113aa336706f1170516` | `JAVA_KOTLIN` | None (Pure Java) | `CRITICAL` (100.0 pts) |
| `suspicious_surveillance_sample.apk` | `com.covert.monitor` | `b34718fd281230440b00c88bb2fa6d92031732adcff32df732c4d67d89859e48` | `JAVA_KOTLIN` | None (Pure Java) | `CRITICAL` (95.4 pts) |
| `network_positive_sample.apk` | `com.spyaware.network` | `3656b42c97839a9ec3881602dadf0eb20ba4f0bc4877caa1f58719142e662f86` | `JAVA_KOTLIN` | None (Pure Java) | `LOW` (24.8 pts) |

---

## 14. Known Limitations

1. **Frida Dynamic Instrumentation:** Frida dynamic hooking server is not running on the host; dynamic analysis continues to rely on authoritative kernel and Android OS telemetry (`dumpsys`, `logcat`, `/proc/net/tcp`).
2. **Encrypted Network Traffic:** Deep packet payload inspection (TLS/HTTPS decryption) is reserved for the upcoming Stage 2C mitmproxy milestone.
3. **Automated Deep UI Monkey Navigation:** Synthetic exploration launches main activities, but complex multi-screen navigation (e.g. login walls) requires automated UI agent interaction.
4. **Physical Device Non-Rooted Extraction:** On non-rooted physical devices, applications marked `allowBackup=false` with protected APK paths cannot be pulled via ADB without user debugging authorization.

---

## 15. Incomplete Tasks

None. All objectives of Milestone M3 (M3.0 Intake, M3.1 Compatibility, M3.2 Discovery, M3.3 Static enhancements, M3.5 Correlation, M3.6 API & Frontend, M3.7 Tests & Documentation) were implemented, tested, and validated.

---

## 16. Dependency or Environment Blockers

No blockers encountered. The host environment provides Python 3.12, Android SDK under `~/Android/Sdk`, KVM hardware virtualization at `/dev/kvm`, Node.js v20+, and Vite 8.

---

## 17. Commands Required to Launch the Backend and Frontend

### Starting the Backend Server
```bash
cd ~/AndroidStudioProjects/SpyAware-Analyzer
source ./venv/bin/activate
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
*API Swagger documentation available at:* `http://127.0.0.1:8000/docs`

### Starting the Frontend Development Server
```bash
cd ~/AndroidStudioProjects/SpyAware-Analyzer/frontend
npm run dev -- --host
```
*Frontend interface available at:* `http://127.0.0.1:5173`

### Executing Full Test Suites
```bash
# Backend pytest suite (268 tests)
./venv/bin/pytest tests/ -v

# Frontend unit tests (24 tests)
cd frontend && npm test -- --watchAll=false

# Frontend production build
cd frontend && npm run build
```

---

## 18. Suggested Next Milestone

**Milestone M4: Stage 2C Network Deep Inspection & Automated Agent UI Traversal**
- **MITM TLS Decryption:** Integrate mitmproxy with automated CA certificate insertion into Android trust store for full HTTPS request/response audit.
- **Autonomous UI Exploration Agent:** Implement automated accessibility tap generation and text field filling to bypass landing screens and stimulate background surveillance routines.
- **Bluetooth Low Energy (BLE) Observation:** Implement Stage 2D BLE scanning monitor to detect hidden AirTag and Tile surveillance beacons.
