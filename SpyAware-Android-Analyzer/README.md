# SpyAware Android Analyzer

**Android Installed Application Interface & Analysis Wrapper**

Part of the [SpyAware](https://github.com/TINKU6113/SpyAware) mobile surveillance risk assessment platform.

---

## Overview

**SpyAware Android Analyzer** is a native Android application engineered to inventory installed applications, submit packages to the **SpyAware Analyzer** backend service for surveillance risk evaluation, render interactive security analysis findings, and trigger official uninstall confirmations for critical-risk applications.

### Key Capabilities

1. **Installed Application Inventory**:
   - Queries and catalogs user-installed packages using Android's `QUERY_ALL_PACKAGES` capability.
   - Extracts application labels, package identifiers, version metadata, and package paths.

2. **Backend Submission & Synchronization**:
   - Connects to the **SpyAware Analyzer** REST API to perform static bytecode, manifest, and permission evaluation.
   - Configurable network endpoint with preconfigured presets for Android Emulator (`10.0.2.2:8000`), USB ADB reverse proxy (`localhost:8000`), or custom LAN addresses.

3. **Critical-Risk Remediation Workflow**:
   - Applications identified with a risk rating in the **CRITICAL** tier (75–100) trigger the remediation interface.
   - Dispatches Android's official system package uninstaller (`ACTION_UNINSTALL_PACKAGE`) to safely remove surveillance applications.
   - **Protection Safeguard**: SpyAware strictly prohibits initiating self-uninstallation through this workflow.

4. **Module Launcher & Integration**:
   - Features quick-launch cards for companion surveillance detection modules including **SpyAware BLE**.

---

## Quick Download

- [Download SpyAware Android Analyzer Debug APK](apk/SpyAware-Android-Analyzer-debug.apk)
- [View APK Documentation and Verification Details](apk/README.md)

---

## Architecture

```
Android Device / Emulator
  │
  ▼
Native Kotlin Shell (MainActivity)
  ├── InstalledAppManager (Package Discovery)
  ├── CriticalRiskUninstallHandler (Official Uninstaller Intent)
  └── BackendPreferences & HealthChecker
        │
        ▼
Android WebView (WebViewAssetLoader @ appassets.androidplatform.net)
  └── Bundled Responsive Operations Dashboard
        │
        ▼ (HTTP REST)
SpyAware Analyzer Backend (@ Configured IP : 8000)
  ├── Static Manifest & Multi-DEX Analysis
  ├── Heuristic Permission Rule Engine
  └── Aggregated 0-100 Risk Engine Scoring
```

---

## Prerequisites & Compatibility

- **Android Version**: Android 8.0 Oreo (API Level 26) through Android 15 (API Level 35)
- **Build Tools**: Android Gradle Plugin 8.8+, Gradle 8.11+
- **JDK**: Java Development Kit 17 or higher
- **Android SDK**: Compile SDK 35 (or 37 ext 1)

---

## Building from Source

From the repository root or module directory:

```bash
cd SpyAware-Android-Analyzer

# Run unit tests
./gradlew test

# Compile debug APK
./gradlew assembleDebug
```

The resulting binary will be generated at:
```
app/build/outputs/apk/debug/app-debug.apk
```

---

## Installing & Running

### Using ADB

```bash
# Install to connected device or emulator
adb install -r apk/SpyAware-Android-Analyzer-debug.apk

# Launch the application
adb shell am start -n com.spyaware.analyzer/.MainActivity
```

---

## Backend Connectivity Configuration

To analyze applications, the Android app requires access to a running **SpyAware Analyzer** instance:

1. **Start the backend server** (see [SpyAware-Analyzer](../SpyAware-Analyzer/README.md)):
   ```bash
   cd ../SpyAware-Analyzer
   uvicorn backend.main:app --host 0.0.0.0 --port 8000
   ```

2. **Configure network in the Android app**:
   - **Android Emulator**: In the app's settings dialog, select **Emulator (10.0.2.2:8000)**.
   - **USB ADB Reverse Proxy**: Run `adb reverse tcp:8000 tcp:8000` and select **ADB Reverse (localhost:8000)**.
   - **Physical Wi-Fi Connection**: Enter `http://<YOUR_LAN_IP>:8000`.
   - Tap **Test Connection** to verify `/api/health` status, then tap **Save & Reload**.

---

## Source Tree Structure

```
SpyAware-Android-Analyzer/
├── app/
│   ├── build.gradle.kts
│   ├── proguard-rules.pro
│   └── src/
│       ├── main/
│       │   ├── AndroidManifest.xml
│       │   ├── assets/              # WebView UI dashboard bundle & icons
│       │   ├── java/com/spyaware/analyzer/
│       │   │   ├── MainActivity.kt
│       │   │   ├── InstalledAppManager.kt
│       │   │   ├── CriticalRiskUninstallHandler.kt
│       │   │   ├── BackendHealthChecker.kt
│       │   │   ├── BackendPreferences.kt
│       │   │   ├── ModuleLauncher.kt
│       │   │   ├── ModuleInstallManager.kt
│       │   │   ├── SettingsDialog.kt
│       │   │   └── WebAppInterface.kt
│       │   └── res/                 # Layouts, drawables, strings
│       └── test/                    # Unit tests
├── apk/
│   ├── README.md
│   └── SpyAware-Android-Analyzer-debug.apk
├── gradle/
├── build.gradle.kts
├── settings.gradle.kts
├── gradlew
├── gradlew.bat
└── README.md
```
