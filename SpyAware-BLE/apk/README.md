# SpyAware BLE — APK Distribution

## Package Metadata

- **Filename**: `SpyAware-BLE-debug.apk`
- **Application ID**: `com.example.spyaware`
- **Module**: SpyAware BLE
- **Build Type**: Debug (`assembleDebug`)
- **Version**: 1.0 (`versionCode 1`)
- **Binary Size**: ~15.1 MB
- **Signature**: Android Debug Keystore (`androiddebugkey`)

---

## Module Overview

The **SpyAware BLE** application is a standalone defensive Android application designed to detect and evaluate nearby Bluetooth Low Energy (BLE) surveillance devices, covert beacons, trackers (such as AirTags, SmartTags, and unbonded tracking peripherals), and potential stalking devices.

### Key Capabilities

1. **Active & Passive BLE Scanning**: Continuously discovers and monitors surrounding BLE transmitters.
2. **RSSI-Based Proximity Estimation**: Tracks received signal strength indicators (RSSI) across multiple time samples to estimate distance and moving proximity.
3. **Potential Targets & Threat Identification**: Flags suspicious devices that exhibit recurring beaconing patterns or follow user movement across location points.
4. **Known Device Registry**: Allows users to register legitimate devices (e.g. personal headphones, smartwatches) as trusted to filter out benign background noise.
5. **Location Trail Mapping**: Visualizes observed device positions and GPS coordinates on an interactive Google Map.
6. **Detailed Device Reporting**: Generates exportable security and evidence reports with RSSI history graphs.

---

## Platform & Compatibility Requirements

- **Minimum Android Version**: Android 12 Snow Cone (API Level 31)
- **Target Android Version**: Android 16 Baklava (API Level 36)
- **Hardware Requirements**: Bluetooth 4.0+ Low Energy radio, GPS / Location sensor
- **Architecture**: Universal (supports ARM64-v8a, ARMeabi-v7a, x86_64, x86)

---

## Installation Instructions

### Option 1: Using ADB (Recommended for Developers)

Ensure USB debugging is enabled on your device:

```bash
adb install -r SpyAware-BLE-debug.apk
```

### Option 2: Sideloading via Device

1. Transfer `SpyAware-BLE-debug.apk` to your Android device.
2. Open your device file browser and select the APK.
3. Enable "Install unknown apps" permission for your file manager if prompted.
4. Tap **Install** to complete installation.

---

## Required Android Runtime Permissions

To function effectively, the app requests the following runtime permissions:

- `android.permission.BLUETOOTH_SCAN`: Discovers nearby Bluetooth Low Energy peripherals without requiring user pairing.
- `android.permission.BLUETOOTH_CONNECT`: Reads peripheral GATT characteristics, device names, and signal metadata.
- `android.permission.ACCESS_FINE_LOCATION`: Required by the Android operating system for Bluetooth LE beacon observation and precise coordinate capture for target mapping.
- `android.permission.ACCESS_COARSE_LOCATION`: Fallback network-based location capture.

---

## Known Limitations

- **Development Build**: Signed with the standard debug certificate.
- **Hardware Dependency**: Cannot discover BLE devices on emulators lacking host Bluetooth passthrough.
- **Maps API Key**: Interactive Google Maps view requires a valid Google Maps API Key provided in `local.properties` during source compilation.
