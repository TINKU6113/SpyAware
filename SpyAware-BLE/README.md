# SpyAware BLE

**Defensive Android Bluetooth Low Energy Surveillance Detection Application**

Part of the [SpyAware](https://github.com/TINKU6113/SpyAware) mobile surveillance risk assessment platform.

---

## Overview

**SpyAware BLE** is a native Android application designed to discover, track, and evaluate nearby Bluetooth Low Energy (BLE) devices to detect covert tracking beacons, commercial tags (such as AirTags, SmartTags, and Tile devices), and clandestine surveillance peripherals.

### Core Capabilities

1. **Active & Passive BLE Observation**:
   - Continuously scans 2.4 GHz BLE advertisement packets in background and foreground.
   - Captures advertising interval metadata, transmission power (`txPower`), and device MAC identifiers.

2. **RSSI-Based Proximity & Signal Tracking**:
   - Maintains rolling RSSI history for each observed device.
   - Computes weighted signal averages and estimates dynamic distance proximity.
   - Detects signal convergence indicative of stationary trackers or moving surveillance devices following the user.

3. **Potential Targets & Threat Heuristics**:
   - Identifies candidate stalking devices based on recurring encounters across distinct geographic coordinates.
   - Differentiates between transient benign devices (e.g., passing pedestrian smartphones) and persistent tracking devices.

4. **Known Device Registry**:
   - Whitelists user-owned trusted Bluetooth devices (e.g. personal headphones, smartwatches, vehicle infotainment) to suppress benign false positives.

5. **Interactive Location Trail & Map**:
   - Plots encounter coordinates and user location tracks on an interactive Google Map.
   - Visualizes device encounter frequency along travel routes.

6. **Evidence & Threat Report Generation**:
   - Compiles structured security reports documenting device identifiers, first/last seen timestamps, signal graphs, and location history.
   - Supports export for documentation and defensive analysis.

---

## Quick Download

- [Download SpyAware BLE Debug APK](apk/SpyAware-BLE-debug.apk)
- [View APK Documentation and Verification Details](apk/README.md)

---

## Architecture & Source Organization

```
SpyAware-BLE/
├── app/
│   ├── build.gradle.kts
│   ├── proguard-rules.pro
│   └── src/
│       ├── main/
│       │   ├── AndroidManifest.xml
│       │   ├── java/com/example/spyaware/
│       │   │   ├── activities/
│       │   │   │   ├── MainActivity.java                # Scanning dashboard & device list
│       │   │   │   ├── DeviceDetailsActivity.java       # Detailed signal telemetry
│       │   │   │   ├── DeviceReportActivity.java        # Structured evidence export
│       │   │   │   ├── KnownDevicesActivity.java        # Trusted device management
│       │   │   │   ├── PotentialHarmfulActivity.java    # Threat detection view
│       │   │   │   ├── PotentialTargetsMapActivity.java # Google Maps geospatial trails
│       │   │   │   └── RadarView.java                   # Visual proximity radar
│       │   │   ├── bluetooth/
│       │   │   │   ├── BLEScanner.java                  # Low-level BluetoothLeScanner
│       │   │   │   └── BleDeviceRegistry.java           # Device cache & RSSI tracking
│       │   │   ├── model/
│       │   │   │   ├── DeviceModel.java                 # Device state & observation history
│       │   │   │   ├── KnownDevice.java                 # Trusted device record
│       │   │   │   ├── KnownDeviceRegistry.java         # Whitelist storage
│       │   │   │   ├── TargetLocationPoint.java         # Coordinate trail record
│       │   │   │   └── UserLocationPoint.java           # User location snapshot
│       │   │   ├── report/                              # PDF/Data export & graph rendering
│       │   │   └── security/
│       │   │       ├── AlertEngine.java                 # Alert notification dispatcher
│       │   │       └── RiskEngine.java                  # RSSI and persistence scoring
│       │   └── res/                                     # Layouts, themes, resources
│       └── test/                                        # Unit test suites
├── apk/
│   ├── README.md
│   └── SpyAware-BLE-debug.apk
├── gradle/
├── build.gradle.kts
├── settings.gradle.kts
├── gradlew
├── gradlew.bat
├── Dockerfile
├── .dockerignore
└── README.md
```

---

## System Requirements & Compatibility

- **Operating System**: Android 12 (API Level 31) through Android 16 (API Level 36)
- **Bluetooth Hardware**: Bluetooth 4.0+ Low Energy (BLE) radio
- **Location Hardware**: GPS receiver for geotagged tracking detection
- **Build Toolchain**: Android Gradle Plugin 9.3+, Gradle 9.5+, JDK 17 (or 21)

---

## Building from Source

### 1. Configure Local Properties (Google Maps API Key)

The mapping feature requires a Google Maps Android API Key. Create a `local.properties` file in `SpyAware-BLE/` (this file is excluded from Git):

```properties
sdk.dir=/path/to/your/android/sdk
MAPS_API_KEY=YOUR_GOOGLE_MAPS_API_KEY
```

> **Note**: If `MAPS_API_KEY` is omitted, the application compiles and runs normally; only the Google Maps activity requires a valid key for tile rendering.

### 2. Execute Tests & Assemble APK

```bash
cd SpyAware-BLE

# Run unit tests
./gradlew test

# Compile debug APK
./gradlew assembleDebug
```

The compiled binary will be placed at:
```
app/build/outputs/apk/debug/app-debug.apk
```

---

## Installing & Running

### Using ADB

```bash
# Sideload APK to connected device
adb install -r apk/SpyAware-BLE-debug.apk

# Launch main scanning activity
adb shell am start -n com.example.spyaware/.activities.MainActivity
```

---

## Runtime Permissions

The application requests the following Android runtime permissions:

| Permission | Purpose |
|---|---|
| `BLUETOOTH_SCAN` | Discover nearby unbonded BLE peripherals |
| `BLUETOOTH_CONNECT` | Query peripheral names and signal characteristics |
| `ACCESS_FINE_LOCATION` | Required by Android for BLE scanning and GPS coordinate trails |
| `ACCESS_COARSE_LOCATION` | Approximate location fallback |

---

## Limitations

- **Hardware Requirement**: BLE scanning cannot function on emulators without Bluetooth passthrough hardware.
- **Randomized MAC Addresses**: Modern mobile devices frequently rotate MAC addresses (`RPA`), which may register as multiple distinct devices over extended periods.
- **Debug Build**: The provided APK is signed with a development key for research and evaluation purposes.
