# SpyAware — Integrated Mobile Surveillance Risk Assessment

**Defensive mobile security suite for identifying covert surveillance, commercial stalkerware, and clandestine RF tracking.**

---

## Project Overview

**SpyAware** is a modular mobile security ecosystem engineered to detect technical indicators of covert surveillance and unauthorized tracking. The project consolidates three specialized modules targeting different facets of the mobile threat landscape:

1. **[SpyAware Android Analyzer](SpyAware-Android-Analyzer/)**
   - Native Android application wrapper and user interface.
   - Discovers and inventories installed applications on the host device.
   - Submits application packages to the Python backend for static bytecode and permission analysis.
   - Renders interactive risk assessments and technical evidence findings.
   - Implements a verified critical-risk uninstall workflow via Android's official system package installer, while protecting SpyAware from self-removal.

2. **[SpyAware Analyzer](SpyAware-Analyzer/)**
   - High-performance Python FastAPI analysis backend.
   - Parses APK structures, manifests, multi-DEX bytecode, native libraries, and permission declarations.
   - Evaluates multi-permission synergy rules (e.g. camera + microphone + background location exfiltration).
   - Computes bounded 0–100 risk assessments via an explainable peak-and-mean scoring formula across four risk tiers (LOW, MEDIUM, HIGH, CRITICAL).
   - Features automated Stage 2B dynamic emulator behavioral analysis and REST API endpoints.

3. **[SpyAware BLE](SpyAware-BLE/)**
   - Standalone native Android application for nearby Bluetooth Low Energy (BLE) observation.
   - Detects unwanted tracking beacons, unbonded peripherals, and commercial tags (AirTags, SmartTags).
   - Maintains rolling RSSI history and calculates proximity and signal convergence.
   - Features a known-device whitelist, travel route geospatial mapping, and structured evidence report generation.

---

## Direct APK Downloads

Pre-built debug application packages are available directly in their dedicated distribution directories:

- 📱 **[Download SpyAware Android Analyzer APK](SpyAware-Android-Analyzer/apk/SpyAware-Android-Analyzer-debug.apk)** (~18.2 MB)  
  *Installed application scanner & backend analysis interface*  
  👉 [View Android Analyzer APK Release Notes & Installation Details](SpyAware-Android-Analyzer/apk/README.md)

- 📡 **[Download SpyAware BLE APK](SpyAware-BLE/apk/SpyAware-BLE-debug.apk)** (~15.1 MB)  
  *Bluetooth Low Energy tracker & proximity surveillance detector*  
  👉 [View BLE APK Release Notes & Installation Details](SpyAware-BLE/apk/README.md)

> **Note**: Both APKs are signed with the Android development debug keystore for research, evaluation, and side-by-side testing.

---

## Module Relationship & System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                          User Environment                              │
└────────────────────────────────────────────────────────────────────────┘
          │                                              │
          ▼                                              ▼
┌───────────────────────────────────┐          ┌─────────────────────────┐
│    SpyAware Android Analyzer      │          │      SpyAware BLE       │
│     (com.spyaware.analyzer)       │          │ (com.example.spyaware)  │
│  - Installed App Inventory        │          │  - 2.4 GHz BLE Scanner  │
│  - WebView Operations Dashboard   │          │  - RSSI History Graphs  │
│  - Critical-Risk Uninstaller      │          │  - Known Device List    │
│  - Module Launcher Cards          │          │  - Google Maps Trails   │
└───────────────────────────────────┘          └─────────────────────────┘
          │ (HTTP REST / JSON)                               ▲
          │                                                  │ (Independent
          ▼                                                  │  RF Observer)
┌────────────────────────────────────────────────────────────┴───────────┐
│                        SpyAware Analyzer Backend                       │
│                        (FastAPI Service @ :8000)                       │
│  ├── Static Analyzer: Manifests, DEX strings, hardware APIs, native binaries │
│  ├── Permission Engine: Explainable individual & synergistic rules     │
│  ├── Risk Engine: Bounded peak-and-mean multi-module aggregation (0-100)│
│  └── Dynamic Sandbox: Isolated AVD emulator execution & OS telemetry   │
└────────────────────────────────────────────────────────────────────────┘
```

### Current Integration Status
- **Implemented Integration**:
  - The **SpyAware Android Analyzer** connects directly to the **SpyAware Analyzer** backend via HTTP REST endpoints (`/api/health`, `/api/analyze`, `/api/analysis/{id}`).
  - The Android Analyzer includes module integration and launcher capabilities allowing users to launch the companion **SpyAware BLE** application when installed on the device.
- **Independent Execution**:
  - **SpyAware BLE** operates as an independent Android application dedicated to physical RF surveillance detection and does not depend on a running Python backend for its scanning or mapping operations.
  - Future milestones plan to unify BLE telemetry data into the backend's multi-module analysis reports.

---

## Repository Directory Guide

```
SpyAware/
├── .github/
│   └── workflows/
│       └── ci-cd.yml                     # Continuous integration workflow
├── .gitignore                            # Root Git hygiene and ignore rules
├── README.md                             # Project overview and guide
│
├── SpyAware-Android-Analyzer/            # Android installed-application wrapper
│   ├── app/                              # Android application source module
│   │   ├── src/main/java/                # Kotlin source files
│   │   ├── src/main/assets/              # WebView dashboard assets
│   │   ├── src/test/                     # Unit test suites
│   │   └── build.gradle.kts              # Application build script
│   ├── apk/
│   │   ├── README.md                     # Android Analyzer APK release notes
│   │   └── SpyAware-Android-Analyzer-debug.apk # Debug APK binary
│   ├── gradle/                           # Gradle wrapper distribution
│   ├── build.gradle.kts                  # Root Gradle build script
│   ├── settings.gradle.kts               # Module settings
│   ├── gradlew / gradlew.bat             # Gradle wrapper scripts
│   ├── .gitignore                        # Module-specific ignore rules
│   └── README.md                         # Android Analyzer documentation
│
├── SpyAware-Analyzer/                    # Python FastAPI analysis backend
│   ├── backend/                          # FastAPI application and REST routes
│   │   ├── main.py                       # Application entrypoint (port 8000)
│   │   ├── api/router.py                 # REST endpoint definitions
│   │   ├── models/                       # Pydantic data schemas
│   │   └── services/                     # Analysis service orchestrator
│   ├── analyzers/                        # Static, permission, and dynamic engines
│   │   ├── static/analyzer.py            # Manifest and DEX bytecode inspection
│   │   ├── permissions/analyzer.py       # Permission analyzer
│   │   └── dynamic/                      # Emulator sandbox & telemetry observers
│   ├── risk_engine/                      # Bounded 0-100 risk calculation logic
│   ├── samples/                          # Synthetic sample APKs & test fixtures
│   ├── tests/                            # Automated pytest test suites
│   ├── docs/                             # Engineering and audit reports
│   ├── frontend/                         # React/TypeScript web operations dashboard
│   ├── requirements.txt                  # Python dependencies
│   ├── .gitignore                        # Backend ignore rules
│   └── README.md                         # Backend setup and API documentation
│
└── SpyAware-BLE/                         # Android BLE surveillance application
    ├── app/                              # Android application source module
    │   ├── src/main/java/                # Java source files (scanning, radar, map)
    │   ├── src/test/                     # Unit test suites
    │   └── build.gradle.kts              # Application build script
    ├── apk/
    │   ├── README.md                     # BLE APK release notes & permissions
    │   └── SpyAware-BLE-debug.apk        # Debug APK binary
    ├── gradle/                           # Gradle wrapper distribution
    ├── build.gradle.kts                  # Root Gradle build script
    ├── settings.gradle.kts               # Module settings
    ├── gradlew / gradlew.bat             # Gradle wrapper scripts
    ├── Dockerfile                        # Containerized build definition
    ├── .dockerignore                     # Docker build exclusions
    ├── .gitignore                        # Module-specific ignore rules
    └── README.md                         # BLE application documentation
```

---

## Quick-Start Guides

### 1. Setting Up the SpyAware Analyzer Backend

The backend requires **Python 3.10+** (Python 3.12 recommended).

```bash
# Navigate to the backend directory
cd SpyAware-Analyzer

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt

# Run test suite to verify installation
pytest tests/

# Start the FastAPI server (default port: 8000)
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

- **Interactive API Documentation**: Navigate to `http://localhost:8000/docs` or `http://localhost:8000/redoc`.
- **Health Verification**: Check `http://localhost:8000/api/health`.

---

### 2. Setting Up SpyAware Android Analyzer

The Android Analyzer requires **JDK 17+** and **Android SDK 35+**.

#### Building from Source:
```bash
cd SpyAware-Android-Analyzer

# Run automated unit tests
./gradlew test

# Assemble debug binary
./gradlew assembleDebug
```
Output APK: `app/build/outputs/apk/debug/app-debug.apk`

#### Installing via ADB:
```bash
adb install -r apk/SpyAware-Android-Analyzer-debug.apk
```

#### Network Configuration for Backend Connectivity:
Open the application on your device or emulator and configure the backend URL via the **Settings** gear icon:
- **Android Emulator**: Use preset `http://10.0.2.2:8000`.
- **USB Reverse Tethering**: Run `adb reverse tcp:8000 tcp:8000` on your host machine, then select `http://localhost:8000`.
- **Local Wi-Fi Network**: Ensure phone and computer are on the same Wi-Fi, find your computer's LAN IP (`ip addr show`), and enter `http://<YOUR_LAN_IP>:8000`.

---

### 3. Setting Up SpyAware BLE

SpyAware BLE requires **Android 12+ (API 31+)**, physical Bluetooth hardware, and **JDK 17+**.

#### Local Configuration:
Create `SpyAware-BLE/local.properties` (never committed to Git) with your Android SDK path and optional Google Maps key:
```properties
sdk.dir=/path/to/android-sdk
MAPS_API_KEY=YOUR_OPTIONAL_GOOGLE_MAPS_KEY
```

#### Building from Source:
```bash
cd SpyAware-BLE

# Run unit tests
./gradlew test

# Assemble debug binary
./gradlew assembleDebug
```
Output APK: `app/build/outputs/apk/debug/app-debug.apk`

#### Installing via ADB:
```bash
adb install -r apk/SpyAware-BLE-debug.apk
```

---

## Defensive Security & Responsible Use

> **Disclaimer**: SpyAware is intended strictly for defensive security research, personal device auditing, and surveillance risk mitigation. Technical indicators (such as hardware sensor permissions, accessibility components, and Bluetooth advertisement beacons) do **not** definitively prove malicious intent. Legitimate software such as parental controls, navigation apps, enterprise MDMs, and audio players utilize similar capabilities.
>
> Users and researchers are responsible for complying with applicable local telecommunications, privacy, and wiretapping laws before analyzing software or intercepting radio transmissions.

---

## Licensing Information

No formal open-source license has been specified for this repository yet. All rights remain reserved by the repository owner ([@TINKU6113](https://github.com/TINKU6113)). Contributions, redistributions, and usage permissions are subject to owner authorization.
