# SpyAware Network — APK Distribution

## Package Metadata

- **Filename**: `SpyAware-Network-debug.apk`
- **Application ID**: `com.spyaware.network`
- **Module**: SpyAware Network (Module 4: Network Security Analyzer)
- **Build Type**: Debug (`assembleDebug`)
- **Version**: 0.1 (`versionCode 1`, `versionName "0.1-stage1"`)
- **Binary Size**: ~7.4 MB (7,415,086 bytes)
- **SHA-256**: `72264A7D02F81C06BB0DC3B064EBCE38F015CBB642CDF064793EF18A3D473E90`
- **Signature**: Android Debug Keystore (`androiddebugkey`)

---

## Module Overview

The **SpyAware Network** application is a defensive, on-device network traffic monitor engineered to identify spyware, covert surveillance telemetry, and unauthorized background data exfiltration without requiring device root privileges.

### Key Capabilities

1. **Rootless Local VPN Packet Interception**:
   - Utilizes Android's `VpnService` to establish a virtual TUN network interface.
   - Transparently processes local IP packets directly on-device.

2. **Native C/C++ Packet Engine (`zdtun`)**:
   - High-throughput C/C++ TUN proxy engine with JNI bridge (`spyawarenative`).
   - Maintains seamless internet connectivity while extracting per-packet telemetry.

3. **Application Attribution & 5-Tuple Flow Reconstruction**:
   - Associates packet flows and active sockets with specific Android UIDs and installed package names.
   - Differentiates foreground user-initiated traffic from stealthy background activity.

4. **Heuristic Behavioral Threat Detection**:
   - **Periodic Beaconing**: Detects low-jitter automated heartbeats typical of Command & Control (C2) servers.
   - **High Upload Anomalies**: Flags abnormal outbound data volume disproportionate to inbound downloads.
   - **Repeated Destinations**: Spots persistent contact with suspicious endpoints.
   - **Off-Screen Telemetry**: Uncovers apps transmitting private data while the device display is locked.
   - **DNS Reputation & DGA**: Sniffs DNS queries and calculates Shannon entropy to detect Domain Generation Algorithms.

5. **Risk Scoring & Audit Logging**:
   - Computes 0–100 risk scores across LOW, MEDIUM, HIGH, and CRITICAL risk tiers.
   - Stores session history and per-app threat evaluations in an encrypted local Room SQLite database.

---

## Platform & Compatibility Requirements

- **Minimum Android Version**: Android 8.0 Oreo (API Level 26)
- **Target Android Version**: Android 14 Upside Down Cake (API Level 34)
- **Architectures**: Universal (ARM64-v8a, ARMeabi-v7a, x86_64, x86)
- **Hardware Requirements**: Active Wi-Fi or Cellular network interface

---

## Installation Instructions

### Option 1: Using ADB (Recommended for Developers)

Ensure USB debugging is enabled on your device:

```bash
adb install -r SpyAware-Network-debug.apk
```

### Option 2: Sideloading via Device

1. Transfer `SpyAware-Network-debug.apk` to your Android device via USB or file transfer.
2. Open your device file browser and select the APK.
3. Allow installation from unknown sources if prompted.
4. Tap **Install** to complete installation.

---

## Required Android Runtime Permissions

- `android.permission.BIND_VPN_SERVICE`: Required for establishing the local TUN virtual network interface.
- `android.permission.INTERNET`: Required for network socket mediation and packet routing.
- `android.permission.QUERY_ALL_PACKAGES`: Required to resolve network socket UIDs to application package names.
- `android.permission.POST_NOTIFICATIONS`: Required for active monitoring status notifications and high-risk threat alerts.

---

## Known Limitations

- **Development Build**: Signed with the standard debug certificate.
- **VPN Conflict**: Android permits only one active VPN service simultaneously. Ensure other third-party VPN apps are disconnected before starting monitoring.
