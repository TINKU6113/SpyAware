# SpyAware Analyzer
**Android Covert Surveillance Analysis Platform**

SpyAware Analyzer is a defensive, standalone Android APK static and permission analysis system engineered to detect technical indicators associated with covert surveillance, commercial stalkerware, and unauthorized telemetry.

Designed with a modular REST architecture, SpyAware Analyzer evaluates Android applications against explainable surveillance rules without executing untrusted code, generating structured JSON risk assessments and rendering findings in a light-themed security operations dashboard.

---

## Important Defensive Analysis Disclaimer

> **Critical Notice**: Static analysis indicators and permission declarations do **not** prove malicious intent or confirm illegal surveillance. Legitimate applications (such as mapping navigators, video conferencing suites, parental controls, and enterprise device managers) legitimately request sensitive Android permissions and invoke hardware APIs. Risk ratings reflect the presence of technical capabilities and synergistic patterns associated with covert monitoring, not definitive proof of malice.

---

## Key Features & Capabilities (v1.0 MVP)

1. **Static APK Analyzer**:
   - Parses manifest components (`activities`, `services`, `receivers`, `providers`) and exported flags.
   - Identifies background persistence mechanisms (`RECEIVE_BOOT_COMPLETED`, `QUICKBOOT_POWERON`).
   - Detects invasive service declarations (`AccessibilityService`, `BIND_ACCESSIBILITY_SERVICE`).
   - Scans DEX bytecode string tables and method references for hardware access indicators:
     - Camera sensors (`android.hardware.Camera`, `CameraManager`, `takePicture`)
     - Microphone recording (`AudioRecord`, `MediaRecorder`, `setAudioSource`)
     - Physical geolocation (`LocationManager`, `FusedLocationProviderClient`)
     - Telephony & SMS interception (`SmsManager`, `CallLog`, `TelephonyManager`)
     - Contacts harvesting (`ContactsContract`)
     - Screen capture & streaming (`MediaProjection`, `createVirtualDisplay`)
   - Audits native binary shared libraries (`.so` files across ARM/x86 ABIs).
   - Identifies suspicious strings, shell execution invocations (`/system/bin/sh`, `su`, `chmod`), and non-standard remote IP endpoints.

2. **Dedicated Permission Analyzer**:
   - Evaluates sensitive permissions using an explainable, weighted scoring system (e.g. `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `RECORD_AUDIO`, `CAMERA`, `ACCESS_BACKGROUND_LOCATION`).
   - Implements multi-permission surveillance combination rules:
     - **Dual Audio/Video**: `CAMERA` + `RECORD_AUDIO`
     - **Full Situational Triad**: `CAMERA` + `RECORD_AUDIO` + `LOCATION`
     - **Covert Tapjacking Synergy**: `ACCESSIBILITY` + `SYSTEM_ALERT_WINDOW`
     - **Reboot Survival**: `ACCESSIBILITY` + `RECEIVE_BOOT_COMPLETED`
     - **Stealth Persistence**: `RECEIVE_BOOT_COMPLETED` + `FOREGROUND_SERVICE`
     - **Sensor Exfiltration Pipeline**: Sensitive sensor permissions + `INTERNET`

3. **Common Explainable Risk Engine**:
   - Aggregates findings from active modules into normalized 0–100 scores.
   - Employs a peak-and-mean weighted formula: $\text{Overall} = 0.60 \times \max(\text{scores}) + 0.40 \times \text{mean}(\text{scores})$ to ensure potent critical indicators are never diluted while rewarding multi-module corroboration.
   - Enforces four standard risk tiers:
     - `0 – 24`: **LOW**
     - `25 – 49`: **MEDIUM**
     - `50 – 74`: **HIGH**
     - `75 – 100`: **CRITICAL**

4. **REST API**:
   - Endpoints for health checks, static analysis, permission evaluation, full combined analysis, and report retrieval.
   - Automatically stores all generated reports under `reports/{analysis_id}.json`.
   - Enforces a 100 MB upload limit and cleans up temporary files immediately upon analysis completion.

5. **Professional Light UI Dashboard**:
   - Clean, light-themed responsive dashboard built with React 19, TypeScript, Vite, and Tailwind CSS.
   - Features subsystem readiness cards (`AVAILABLE` vs `COMING SOON`), live analysis progress indicators, tabbed findings view, and technical evidence audit tables.
   - Includes quick-load sample presets for instant evaluation.

---

## Directory Architecture

```
SpyAware-Analyzer/
├── backend/
│   ├── main.py                  # FastAPI application entrypoint with CORS
│   ├── api/
│   │   ├── __init__.py
│   │   └── router.py            # REST endpoints (/health, /analyze, /analysis/{id})
│   ├── models/
│   │   ├── __init__.py
│   │   └── analysis.py          # Pydantic schemas for findings, results, and reports
│   └── services/
│       ├── __init__.py
│       └── analysis_service.py   # Analysis orchestrator and report storage service
├── analyzers/
│   ├── __init__.py
│   ├── static/
│   │   ├── __init__.py
│   │   └── analyzer.py          # Static APK manifest and DEX bytecode analyzer
│   ├── permissions/
│   │   ├── __init__.py
│   │   └── analyzer.py          # Dedicated permission analyzer
│   └── dynamic/
│       ├── __init__.py
│       └── stub.py              # Dynamic analysis architectural hook (Milestone 2)
├── risk_engine/
│   ├── __init__.py
│   ├── engine.py                # Multi-module risk aggregation and scoring engine
│   └── rules.py                 # Individual and synergistic permission rules
├── reports/                     # Local JSON analysis report persistence
├── samples/                     # Synthetic test APKs and generator
│   ├── builder.py               # Pure-Python binary APK and DEX builder
│   ├── benign_sample.apk
│   ├── suspicious_surveillance_sample.apk
│   ├── critical_stalkerware_sample.apk
│   ├── malformed_corrupt.apk
│   ├── malformed_no_manifest.apk
│   └── malformed_invalid_manifest.apk
├── tests/                       # Automated pytest suite (24 unit/integration tests)
│   ├── test_permissions.py
│   ├── test_risk_engine.py
│   ├── test_static_analyzer.py
│   └── test_api.py
├── frontend/                    # Vite + React + TypeScript + Tailwind UI
│   ├── src/
│   │   ├── App.tsx              # Main dashboard application
│   │   ├── types.ts             # Frontend TypeScript definitions
│   │   └── index.css            # Tailwind styling setup
│   ├── package.json
│   └── vite.config.ts
├── requirements.txt
└── README.md
```

---

## Subsystem Readiness

| Engine Subsystem | Status | Description |
|---|---|---|
| **Static Analysis** | **AVAILABLE** | Manifest component extraction, DEX API inspection, native binaries |
| **Permission Analysis** | **AVAILABLE** | Weighted indicators, combination synergy evaluation |
| **Dynamic Sandbox (Stage 2B)** | **AVAILABLE** | Isolated Android emulator execution, 11-category behavioral matrix, multi-source OS telemetry (`dumpsys`, `logcat`, `ps -A`) |
| **Network PCAP Analysis** | **COMING SOON** | Stage 2C roadmap: transparent proxying, flow inspection, DNS exfiltration |
| **BLE Surveillance** | **COMING SOON** | Planned tracker beacon scanning and surveillance triangulation |

---

## REST API Specification

### 1. `GET /api/health`
Returns service readiness and subsystem states.
```json
{
  "status": "healthy",
  "service": "SpyAware-Analyzer",
  "version": "1.0.0",
  "modules": {
    "static": "AVAILABLE",
    "permissions": "AVAILABLE",
    "dynamic": "STAGE_2B_AVAILABLE",
    "network": "COMING_SOON",
    "ble": "COMING_SOON"
  }
}
```

### 2. `GET /api/dynamic/environment`
Performs dynamic execution environment diagnostics without triggering an emulator run.
- Checks host availability of `adb`, `emulator`, `avdmanager`, and optional `frida`.
- Detects configured AVDs (including `$SPYAWARE_AVD_NAME` override).
- Checks currently connected/online adb devices.
```json
{
  "adb_available": true,
  "emulator_available": true,
  "avdmanager_available": true,
  "frida_available": false,
  "available_avds": ["Medium_Phone_API_36.1"],
  "running_devices": ["emulator-5554"],
  "selected_avd": "Medium_Phone_API_36.1",
  "ready": true,
  "message": "Dynamic analysis environment is operational (1 AVDs found, 1 device online)"
}
```

### 3. `POST /api/analyze`
Uploads an APK file via `multipart/form-data` and executes the static + permission risk analysis pipeline.
- **Request**: Multipart file under key `file`.
- **Query Parameter**: `dynamic: bool = False` (set to `true` to concurrently execute the Stage 2A dynamic emulator pipeline).
- **Response**: `RiskReport` JSON object (with `module_scores.dynamic` and `dynamic_details` populated when dynamic is enabled).

### 4. `POST /api/analyze/dynamic`
Uploads an APK file to execute the Stage 2A isolated dynamic emulator analysis independently.
- **Request**: Multipart file under key `file`.
- **Response**: `DynamicAnalysisResult` JSON object containing execution metadata, runtime observations, active services, and logcat tail.

### 5. `POST /api/analyze/static`
Uploads an APK file to execute static manifest and DEX bytecode inspection only.

### 6. `POST /api/analyze/permissions`
Executes permission rule evaluation. Accepts either:
- A multipart APK file upload, OR
- A JSON body:
```json
{
  "permissions": [
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION"
  ],
  "target_name": "CustomPermissionSet"
}
```

### 7. `GET /api/analysis/{analysis_id}`
Retrieves a previously computed report from disk (`reports/{analysis_id}.json`).

### 8. `POST /api/analyze/sample/{sample_name}`
Triggers analysis on one of the pre-bundled synthetic sample APKs (`benign_sample`, `suspicious_surveillance_sample`, `critical_stalkerware_sample`).
- **Query Parameter**: `dynamic: bool = False`.

---

## Sample JSON Analysis Report

```json
{
  "analysis_id": "18f08f02-fa32-4740-9e73-b29b6e8a4a16",
  "timestamp": "2026-10-08T16:59:47.316499+00:00",
  "apk_filename": "critical_stalkerware_sample.apk",
  "overall_score": 91.8,
  "risk_level": "CRITICAL",
  "module_scores": {
    "static": 59.0,
    "permissions": 100.0,
    "dynamic": null,
    "network": null,
    "ble": null
  },
  "findings": [
    {
      "category": "STATIC",
      "severity": "CRITICAL",
      "title": "Accessibility Service Component Declared",
      "description": "Application registers an AccessibilityService component. Stalkerware commonly uses accessibility services to log keystrokes...",
      "evidence": "com.spyaware.stalkerware.AccessibilityKeylogger",
      "score": 30.0
    },
    {
      "category": "PERMISSION",
      "severity": "CRITICAL",
      "title": "[Pattern Synergy] Stealth Accessibility & Screen Overlay Synergy",
      "description": "Combination of BIND_ACCESSIBILITY_SERVICE and SYSTEM_ALERT_WINDOW allows an app to intercept user input and display clickjacking overlays.",
      "evidence": "Synergistic permission set matched: BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW",
      "score": 35.0
    }
  ],
  "summary": "CRITICAL risk (91.8/100). The application exhibits high-potency covert surveillance indicators...",
  "disclaimer": "Risk assessment is based on observed indicators and does not by itself prove malicious intent."
}
```

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Backend Setup

```bash
# In the SpyAware-Analyzer root directory:
python3 -m venv venv
source venv/bin/activate

# Install backend dependencies
pip install -r requirements.txt

# Generate synthetic test APKs in samples/
python samples/builder.py

# Verify sample APK signatures using apksigner
apksigner verify --verbose --print-certs samples/benign_sample.apk
```

#### Synthetic Sample Packaging & Signing Architecture
`samples/builder.py` automates the generation and signing of reproducible test APKs:
1. **Manifest Compilation**: Compiles well-formed `AndroidManifest.xml` (targeting modern Android SDK 34) using Android SDK `aapt`.
2. **Bytecode & Native Code Injection**: Bundles synthetic DEX string tables and native `.so` binaries.
3. **Zipalign**: Enforces 4-byte alignment on uncompressed resources via `zipalign -f -p 4`.
4. **Cryptographic Signing**: Signs the APK using `apksigner` with Android v1 (JAR), v2 (APK Signature Scheme), and v3 schemes using a local debug keystore (`~/.android/debug.keystore`, auto-generated with `keytool` if absent).
5. **Verification**: Verifies cryptographic integrity via `apksigner verify --verbose --print-certs`.


### 2. Run Backend Server

```bash
# Activate virtual environment
source venv/bin/activate

# Launch FastAPI with Uvicorn
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
The API documentation is accessible at `http://127.0.0.1:8000/docs`.

### 3. Frontend Setup & Startup

```bash
# In a separate terminal, navigate to the frontend directory:
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```
The web dashboard will be available at `http://localhost:5173`.

### 4. Build Frontend for Production

```bash
cd frontend
npm run build
```

---

---

## Dynamic Analysis Stage 2A & 2B Architecture

The dynamic sandbox operates an isolated, defensive execution pipeline to observe untrusted Android applications safely inside an official Android Virtual Device (AVD) emulator without risking host compromise.

### Execution Pipeline

```
Untrusted APK
  │
  ▼
Static Pre-Inspection (Extract Package Name & Launchable Activity)
  │
  ▼
Dynamic Worker (Temporary Workspace & Timeout Controller)
  │
  ▼
Android Emulator Launch / Reuse Online Device (Headless Mode)
  │
  ▼
Boot & Package Manager Synchronization (sys.boot_completed == 1)
  │
  ▼
Isolated Installation (adb install -r -g)
  │
  ▼
Controlled Launch (am start -n / monkey fallback / safe handling if no activity)
  │
  ▼
Stage 2B Runtime Observation Window (Configurable duration, default 15s)
  ├── dumpsys media.camera (Active CameraHardware & client sessions)
  ├── dumpsys audio (Active AudioRecord / MediaRecorder sessions)
  ├── dumpsys location (Location providers & geofence listeners)
  ├── dumpsys accessibility (Bound/active accessibility service registrations)
  ├── dumpsys media_projection (Active screen streaming tokens)
  ├── dumpsys activity services <pkg> (Active runtime ServiceRecords)
  ├── Linux Process Table (ps -A / UID matching)
  └── Logcat Audit (AndroidRuntime crashes, SMS, persistence triggers)
  │
  ▼
Graceful Teardown & Sanitation (am force-stop -> adb uninstall -> emu kill -> rm workspace)
  │
  ▼
Dynamic Analysis Report & Risk Score Synthesis (Stage 2B)
```

### Stage 2B Runtime Behavioral Observation

Stage 2B implements a strict, explainable distinction between:
1. **"The APK declares a capability"** (Static manifest / DEX bytecode / requested permissions)
2. **"The APK actually performed a sensitive operation during execution"** (Verified dynamic OS telemetry)

#### Target Behavioral Categories & Telemetry Provenance

| Category | Telemetry Provenance Source | Verification Criteria |
|---|---|---|
| **CAMERA** | `dumpsys media.camera` + `logcat` | Active camera client connection registered for package UID/name |
| **MICROPHONE** | `dumpsys audio` + `logcat` | Active `AudioRecord` or `MediaRecorder` capture session |
| **LOCATION** | `dumpsys location` + `logcat` | Active GPS/Network provider listener or geofence request |
| **ACCESSIBILITY** | `dumpsys accessibility` + `logcat` | Active bound service registration (`Bound services:{...}`) in system state. Merely declaring an AccessibilityService in the manifest does NOT trigger `OBSERVED`. |
| **MEDIA_PROJECTION** | `dumpsys media_projection` + `logcat` | Active screen capture or mirroring session token attributed to package |
| **SMS** | `logcat` / telephony | Runtime SMS dispatch, transmission, or incoming broadcast interception |
| **CALL** | `logcat` / telephony | Runtime phone call invocation or telephony audio recording activity |
| **BACKGROUND_SERVICE** | `dumpsys activity services <pkg>` | Actively executing `ServiceRecord` currently running in system state |
| **PERSISTENCE** | `dumpsys` / `logcat` | Runtime boot completion triggers or scheduled job execution |
| **PROCESS** | `ps -A` / Linux proc | Active Linux PID/process table entry attributed to package |
| **CRASH** | `logcat` (`AndroidRuntime`) | Fatal unhandled exception or process abort observed during execution |

#### Status Semantics
- `OBSERVED`: Strong runtime evidence confirmed that the application executed or registered the sensitive operation.
- `NOT_OBSERVED`: Monitored system services and logcat confirmed absence of activity during the execution window.
- `NOT_AVAILABLE`: Specific telemetry mechanism unavailable (e.g. Frida runtime hooks when Frida is not installed on host).
- `ERROR`: Telemetry collector encountered a runtime exception.

#### Conservative Evidence Policy
- **No Inferred Findings**: Static permissions or manifest entries are NEVER converted into runtime findings.
- **Strict Package Attribution**: Telemetry is attributed strictly to the analyzed package name or its runtime UID.
- **Negative Controls**: An idle or benign application requesting sensitive permissions will report `NOT_OBSERVED` across sensor categories.

### Safety & Isolation Guarantees

1. **Zero Host Execution**: Untrusted APK binaries are NEVER executed directly on the host operating system. Execution occurs strictly within the sandboxed Android emulator kernel.
2. **Subprocess Argument Arrays**: All system command invocations use explicit argument arrays (`["adb", "shell", ...]`). `shell=True` is strictly prohibited to eliminate command injection vectors.
3. **Dedicated Temporary Workspaces**: Each analysis job operates in an isolated temporary directory cleaned upon completion.
4. **Enforced Hard Timeouts**:
   - `BOOT_TIMEOUT_SECONDS = 90`
   - `INSTALL_TIMEOUT_SECONDS = 30`
   - `EXECUTION_TIMEOUT_SECONDS = 60`
   - `CLEANUP_TIMEOUT_SECONDS = 30`
5. **Safe Handling of Background/Services-Only APKs**: Applications without a launchable activity are diagnosed with `NO_LAUNCHABLE_ACTIVITY` and uninstalled without false-positive score penalties.
6. **Host Tool Diagnostics**: If host tools or AVDs are missing, the analyzer provides actionable diagnostics rather than crashing.

---

## Running the Automated Test Suite

The test suite validates static analysis, permission scoring, combination rules, risk classification, score bounds, APK signing, dynamic environment discovery, runner execution, observer telemetry, Stage 2B behavioral models, and REST API endpoints:

```bash
source venv/bin/activate
pytest -v tests/
```

**Test Coverage Summary (61 Tests Across 11 Test Suites)**:
- `tests/test_permissions.py` (6 tests): Evaluates benign vs suspicious permission sets, synergy rules, and bounded caps.
- `tests/test_risk_engine.py` (5 tests): Verifies 4-tier risk classification, peak-and-mean aggregation, and module preservation.
- `tests/test_static_analyzer.py` (7 tests): Validates archive handling, manifest parsing, and DEX/AXML extraction.
- `tests/test_apk_signature.py` (3 tests): Validates Android signing certificate presence, v1/v2/v3 signatures, and debug keystore generation.
- `tests/test_dynamic_environment.py` (4 tests): Tests host tool discovery (`adb`, `emulator`, `avdmanager`), AVD parsing, and diagnostics.
- `tests/test_dynamic_observer.py` (5 tests): Verifies runtime surveillance API detection in logcat, crash detection, and service extraction.
- `tests/test_dynamic_stage2b.py` (12 tests): Verifies Stage 2B behavioral models, dumpsys parsing across 11 categories, negative controls (idle permissions remain `NOT_OBSERVED`), accessibility bound validation, process tracking, and backwards compatibility.
- `tests/test_dynamic_runner.py` (6 tests): Validates boot polling, safe APK installation, activity launching with fallback, and dumpsys commands.
- `tests/test_dynamic_worker.py` (4 tests): Tests end-to-end mocked execution orchestration, environment absence handling, and no-launchable-activity handling.
- `tests/test_dynamic_api.py` (3 tests): Tests `GET /api/dynamic/environment`, `POST /api/analyze/dynamic`, and `POST /api/analyze?dynamic=true`.
- `tests/test_api.py` (6 tests): Validates `/api/health`, `/api/analyze`, `/api/analyze/permissions`, report retrieval, and 404 error handling.

---

## Limitations & Dynamic Analysis Roadmap

### Current Stage 2B Scope & Limitations
1. **OS Telemetry-Based**: Stage 2B leverages authoritative Android OS telemetry (`dumpsys`, `logcat`, `ps -A`). This operates robustly without modifying target binaries or requiring root.
2. **Execution Time Window**: Default observation window is 15 seconds (configurable). Behaviors configured with extended time delays will not trigger within this window.
3. **Frida Dynamic Instrumentation**: Frida tool discovery is implemented with graceful fallback (`NOT_AVAILABLE`). When Frida server is not running on the target device, dumpsys OS telemetry is used.
4. **Encrypted Network Interception**: Network endpoints are inspected statically; live TLS traffic interception is reserved for Stage 2C.

### Dynamic Analysis Roadmap (Milestone 2C)
1. **Stage 2C (Mitmproxy / Network PCAP)**: Transparent proxying and flow analysis of HTTP/HTTPS/WebSocket traffic to inspect remote exfiltration endpoints.
2. **Anti-Evasion Hardening**: Patching emulator build properties (`ro.kernel.qemu`, build tags) to bypass basic sandbox detection.
3. **BLE Surveillance Engine**: Integration with Bluetooth scanning subsystems to identify clandestine BLE tracking beacons.
