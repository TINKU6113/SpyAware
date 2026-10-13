# SpyAware Android Analyzer — APK Distribution

## Package Metadata

- **Filename**: `SpyAware-Android-Analyzer-debug.apk`
- **Application ID**: `com.spyaware.analyzer`
- **Module**: SpyAware Android Analyzer
- **Build Type**: Debug (`assembleDebug`)
- **Version**: 1.0.0 (`versionCode 1`)
- **Binary Size**: ~18.2 MB
- **Signature**: Android Debug Keystore (`androiddebugkey`)

---

## Module Overview

The **SpyAware Android Analyzer** is the mobile front-end application and wrapper for installed-application surveillance risk evaluation. It provides:
1. **Installed Application Inventory**: Queries and lists installed packages on the user device.
2. **Analysis Workflow**: Submits selected installed APK packages to the **SpyAware Analyzer** backend service via REST API.
3. **Interactive Light Dashboard**: Renders technical findings, permission usage, DEX bytecode indicators, and multi-module aggregated risk scores.
4. **Critical-Risk Remediation**: Integrates an uninstall confirmation workflow for applications scoring in the CRITICAL risk tier (75–100), dispatching Android's official `ACTION_UNINSTALL_PACKAGE` package installer intent while safeguarding SpyAware from self-removal.

---

## Platform & Compatibility Requirements

- **Minimum Android Version**: Android 8.0 Oreo (API Level 26)
- **Target Android Version**: Android 15 Vanilla Ice Cream (API Level 35)
- **Architecture**: Universal (supports ARM64-v8a, ARMeabi-v7a, x86_64, x86)
- **Network**: Wi-Fi or Cellular network access with reachability to the backend server

---

## Installation Instructions

### Option 1: Using ADB (Recommended for Developers)

Ensure USB debugging is enabled on your device or emulator:

```bash
adb install -r SpyAware-Android-Analyzer-debug.apk
```

### Option 2: Sideloading via Device

1. Copy `SpyAware-Android-Analyzer-debug.apk` to your Android device via USB, Google Drive, or local storage.
2. Open the file manager on your device and tap the APK file.
3. When prompted, permit installation from unknown sources for your file manager.
4. Complete the system package installer prompt.

---

## Backend Connectivity Configuration

This application connects to the **SpyAware Analyzer** backend service for static and heuristic APK analysis:

- **Android Emulator**: Set backend URL to `http://10.0.2.2:8000` (maps to host loopback).
- **Physical Device**: Connect to the same Wi-Fi network as your workstation and set backend URL to `http://<YOUR_COMPUTER_LOCAL_IP>:8000`.
- **In-App Configuration**: Tap the Settings gear icon in the toolbar to enter your backend URL and test connection health before initiating scans.

---

## Required Android Permissions

- `android.permission.INTERNET`: Required to communicate with the FastAPI backend service.
- `android.permission.ACCESS_NETWORK_STATE`: Required to verify local network and backend connectivity.
- `android.permission.QUERY_ALL_PACKAGES`: Required to discover installed applications for analysis.
- `android.permission.REQUEST_DELETE_PACKAGES`: Required to launch official system uninstall prompts for detected high/critical threats.

---

## Known Limitations

- **Development Build**: Built with the Android debug signing certificate; not suitable for production Google Play Store release.
- **Backend Dependency**: Analysis features require an active, reachable SpyAware Analyzer backend instance.
