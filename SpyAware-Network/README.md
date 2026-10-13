# SpyAware Network

**On-Device Network Traffic Monitor for Covert Surveillance Detection & Behavioral Analysis**

Part of the [SpyAware](https://github.com/TINKU6113/SpyAware) mobile surveillance risk assessment platform.

---

## Overview

**SpyAware Network** is a native Android security application engineered to monitor, inspect, and evaluate device network traffic in real time. Operating entirely on-device without requiring root access, it leverages Android's local `VpnService` to capture outbound and inbound IP packets, attribute network flows to individual installed applications, and detect behavioral indicators of spyware, stalkerware, and clandestine command-and-control (C2) activity.

---

## Core Capabilities

### 1. Rootless Local VPN Capture
- Establishes a local virtual TUN interface via Android's `VpnService`.
- Intercepts raw IPv4 packets on-device with zero remote server dependency or cloud exfiltration.
- Transparently routes valid network traffic to preserve normal device connectivity.

### 2. High-Performance Native Bridge (`zdtun`)
- Integrates a C/C++ networking core via JNI (`native-bridge.cpp` and `zdtun`).
- Provides low-overhead packet mediation, TUN-to-SOCKS5 proxying, and raw socket routing without degrading user experience or throughput.

### 3. Application Attribution & Flow Reconstruction
- Maps network sockets and 5-tuple flows (Source IP/Port, Destination IP/Port, Protocol) to Android UIDs via `/proc/net` inspection and `ConnectivityManager`.
- Resolves system UIDs to human-readable installed package names and application metadata.
- Correlates foreground versus background operational state using screen state broadcasting (`ScreenStateReceiver`).

### 4. Layer-7 Protocol Inspection
- **DNS Query Parsing**: Extracts requested domain names, query types, and response records from raw UDP port 53 packets.
- **TLS SNI Sniffing**: Inspects TLS Client Hello handshakes to extract Server Name Indication (SNI) hostnames from encrypted HTTPS connections.
- **Payload Pattern Inspection**: Scans unencrypted traffic for plain text credentials, tracking parameters, or known data leakage signatures.

### 5. Behavioral Heuristics & Anomaly Detection
- **Periodic Beaconing**: Detects low-jitter, recurring transmissions characteristic of spyware polling C2 infrastructure.
- **High Background Uploads**: Flags applications transmitting high volumes of outbound data while operating in the background.
- **Repeated Suspicious Destinations**: Monitors connection frequency to identify persistent connections to unknown or dynamic endpoints.
- **Off-Screen Telemetry**: Uncovers background data exfiltration occurring while the device display is off or locked.
- **DNS Reputation & DGA Detection**: Calculates Shannon entropy on domain labels to spot algorithmically generated domains (DGAs) and excessive DNS churn.

### 6. Explainable Risk Scoring & Audit Logging
- Computes weighted risk scores (0–100) using configurable thresholds defined in `assets/config.json`.
- Categorizes threat levels across four tiers: **LOW**, **MEDIUM**, **HIGH**, and **CRITICAL**.
- Persists traffic sessions and detected findings to a local Room SQLite database for historical forensics.

---

## Quick Download

- 📱 **[Download SpyAware Network Debug APK](apk/SpyAware-Network-debug.apk)** (~7.4 MB)
- 📋 **[View APK Documentation & Verification Details](apk/README.md)**

---

## Architecture & Directory Structure

```
SpyAware-Network/
├── app/
│   ├── build.gradle                              # Application build script & dependencies
│   └── src/
│       └── main/
│           ├── AndroidManifest.xml               # Permissions & service declarations
│           ├── assets/
│           │   └── config.json                   # Heuristic thresholds & scoring weights
│           ├── cpp/                              # Native C/C++ engine
│           │   ├── CMakeLists.txt                # Native build configuration
│           │   ├── native-bridge.cpp             # JNI bridge between Java & zdtun
│           │   └── zdtun/                        # TUN-to-SOCKS5 proxy implementation
│           ├── java/com/spyaware/network/
│           │   ├── MainActivity.java             # Live dashboard & monitoring controls
│           │   ├── HistoryActivity.java          # Historical sessions & forensics view
│           │   ├── SpyAwareVpnService.java       # Local VPN service & TUN lifecycle
│           │   ├── NativeBridge.java             # JNI method bindings
│           │   ├── AppAttributionManager.java    # Socket UID-to-package attribution
│           │   ├── ConnectionTracker.java        # 5-tuple flow state tracker
│           │   ├── BehaviorAnalyzer.java         # Behavioral anomaly detector
│           │   ├── Level1TrafficAnalyzer.java    # Low-level packet inspector
│           │   ├── DnsQueryParser.java           # DNS packet decoder
│           │   ├── DnsReputationManager.java     # Entropy & DGA domain scoring
│           │   ├── TlsSniParser.java             # TLS Client Hello SNI parser
│           │   ├── PayloadAnalyzer.java          # Raw packet content analyzer
│           │   ├── RiskScorer.java               # 0-100 risk score engine
│           │   ├── RiskNotificationManager.java  # Real-time alert notifications
│           │   ├── ScreenStateReceiver.java      # Screen ON/OFF tracking
│           │   ├── MuteList.java                 # Benign app noise suppression
│           │   ├── PacketLog.java                # Packet buffer & logger
│           │   ├── PersistenceManager.java       # Room database manager
│           │   └── db/                           # Room Database entities & DAOs
│           │       ├── AppDataBase.java          # Room database definition
│           │       ├── SessionDao.java           # Session query interface
│           │       ├── AppRiskDao.java           # App risk query interface
│           │       └── SessionEntity.java        # Traffic session database schema
│           └── res/                              # Layouts, drawables, styles, strings
├── apk/
│   ├── README.md                                 # APK release notes & hash verification
│   └── SpyAware-Network-debug.apk                # Pre-built debug APK binary
├── gradle/
│   └── wrapper/
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
├── build.gradle                                  # Root Gradle build script
├── settings.gradle                               # Root project settings
├── gradle.properties                             # Build configuration & JVM settings
├── gradlew / gradlew.bat                         # Gradle wrapper scripts
├── .gitignore                                    # Git ignore rules
└── README.md                                     # Module documentation
```

---

## System Requirements & Compatibility

- **Operating System**: Android 8.0 Oreo (API Level 26) through Android 14 (API Level 34)
- **Architecture**: Universal (supports ARM64-v8a, ARMeabi-v7a, x86_64, x86)
- **Hardware**: Active Wi-Fi or Cellular network connection
- **Permissions**: VpnService approval prompt confirmed by user

---

## Building from Source

### Prerequisites
- **Android Studio** Hedgehog (2023.1.1) or newer
- **Android SDK** API Level 34
- **Android NDK** (version 25.1.8937393 or compatible) and **CMake** (3.22.1+)
- **JDK 17**

### Build Commands

```bash
# Clone the repository
git clone https://github.com/TINKU6113/SpyAware.git
cd SpyAware/SpyAware-Network

# Build debug APK
./gradlew assembleDebug

# Output APK is generated at:
# app/build/outputs/apk/debug/app-debug.apk
```

### Installation via ADB

```bash
adb install -r apk/SpyAware-Network-debug.apk
```

---

## Integration with SpyAware Ecosystem

**SpyAware Network** serves as Module 4 within the SpyAware defense suite:
- **Companion Launcher**: The **SpyAware Android Analyzer** (`com.spyaware.analyzer`) registers Module 4 (`com.spyaware.network`) in its modular dashboard, enabling unified module installation, verification, and launch capabilities.
- **Multi-Vector Defense**: While **SpyAware BLE** investigates physical RF proximity beacons and **SpyAware Analyzer** evaluates installed APK bytecode, **SpyAware Network** secures the active communication channel, uncovering covert data exfiltration and beaconing in real time.
