package com.example.spyaware.bluetooth;

import android.content.Context;
import android.util.Log;

import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.model.TargetLocationPoint;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class BleDeviceRegistry {

    private static final String TAG = "BleDeviceRegistry";
    private static final String CACHE_FILE_NAME = "device_registry_cache.json";

    private static final Map<String, DeviceModel> devices =
            new LinkedHashMap<>();

    private BleDeviceRegistry() {
        // Prevent accidental object creation
    }

    public static synchronized void addDevice(
            String identifier,
            DeviceModel device) {

        if (identifier != null && device != null) {
            devices.put(identifier, device);
        }
    }

    public static synchronized DeviceModel getDevice(
            String identifier) {

        if (identifier == null) {
            return null;
        }
        return devices.get(identifier);
    }

    public static synchronized Map<String, DeviceModel> getDevices() {
        return devices;
    }

    public static synchronized boolean contains(
            String identifier) {

        if (identifier == null) {
            return false;
        }
        return devices.containsKey(identifier);
    }

    public static synchronized void clear() {
        devices.clear();
    }

    /**
     * Persist current registry state to internal storage so observations
     * and device history are retained across scan sessions and restarts.
     */
    public static synchronized void saveToStorage(Context context) {
        if (context == null) {
            return;
        }
        try {
            JSONArray array = new JSONArray();
            for (Map.Entry<String, DeviceModel> entry : devices.entrySet()) {
                DeviceModel device = entry.getValue();
                if (device == null) {
                    continue;
                }
                JSONObject obj = new JSONObject();
                obj.put("mac", device.getMacAddress());
                obj.put("name", device.getDeviceName());
                obj.put("rssi", device.getRssi());
                obj.put("firstSeen", device.getFirstSeen());
                obj.put("lastSeen", device.getLastSeen());
                obj.put("firstSeenTimestamp", device.getFirstSeenTimestamp());
                obj.put("lastSeenTimestamp", device.getLastSeenTimestamp());
                obj.put("packetCount", device.getPacketCount());
                obj.put("manufacturerData", device.getManufacturerData());
                obj.put("serviceUuids", device.getServiceUuids());
                obj.put("txPower", device.getTxPower());
                obj.put("fingerprint", device.getBleFingerprint());
                obj.put("classification", device.getDeviceClassification());
                obj.put("riskScore", device.getRiskScore());
                obj.put("riskLevel", device.getRiskLevel());
                obj.put("referenceRssi", device.getReferenceRssiAtOneMeter());
                obj.put("isCalibrated", device.isCalibrated());

                // RSSI history
                JSONArray rssiArr = new JSONArray();
                for (int r : device.getRssiHistory()) {
                    rssiArr.put(r);
                }
                obj.put("rssiHistory", rssiArr);

                // RSSI timestamps
                JSONArray tsArr = new JSONArray();
                for (long t : device.getRssiTimestamps()) {
                    tsArr.put(t);
                }
                obj.put("rssiTimestamps", tsArr);

                // Target locations
                JSONArray locArr = new JSONArray();
                for (TargetLocationPoint p : device.getTargetLocationHistory()) {
                    JSONObject locObj = new JSONObject();
                    locObj.put("ts", p.getTimestamp());
                    locObj.put("lat", p.getLatitude());
                    locObj.put("lng", p.getLongitude());
                    locObj.put("dist", p.getEstimatedDistance());
                    locObj.put("rssi", p.getRssi());
                    locObj.put("trend", p.getRssiTrend());
                    locObj.put("conf", p.getDistanceConfidence());
                    locArr.put(locObj);
                }
                obj.put("targetLocations", locArr);

                array.put(obj);
            }

            File file = new File(context.getFilesDir(), CACHE_FILE_NAME);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(array.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            Log.e(TAG, "Error saving device registry to storage: " + e.getMessage());
        }
    }

    /**
     * Restore registry state from internal storage if registry is empty.
     */
    public static synchronized void loadFromStorage(Context context) {
        if (context == null) {
            return;
        }
        File file = new File(context.getFilesDir(), CACHE_FILE_NAME);
        if (!file.exists()) {
            return;
        }
        try {
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            }

            JSONArray array = new JSONArray(sb.toString());
            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.getJSONObject(i);
                String mac = obj.optString("mac", "");
                if (mac.isEmpty() || devices.containsKey(mac)) {
                    continue;
                }
                String name = obj.optString("name", "Unknown BLE Device");
                int rssi = obj.optInt("rssi", -100);
                String firstSeen = obj.optString("firstSeen", "--");
                String lastSeen = obj.optString("lastSeen", "--");

                DeviceModel device = new DeviceModel(name, mac, rssi, firstSeen, lastSeen);
                device.setFirstSeenTimestamp(obj.optLong("firstSeenTimestamp", System.currentTimeMillis()));
                device.setLastSeenTimestamp(obj.optLong("lastSeenTimestamp", System.currentTimeMillis()));
                device.setAdvertisementData(
                        obj.optString("manufacturerData", "None"),
                        obj.optString("serviceUuids", "None"),
                        obj.optInt("txPower", Integer.MIN_VALUE)
                );
                device.setBleFingerprint(obj.optString("fingerprint", "Unknown"));
                device.setDeviceClassification(obj.optString("classification", DeviceModel.CLASS_UNKNOWN));
                device.setRiskScore(obj.optInt("riskScore", 0));
                device.setRiskLevel(obj.optString("riskLevel", "LOW"));
                device.setReferenceRssiAtOneMeter(obj.optDouble("referenceRssi", -59.0));

                JSONArray rssiArr = obj.optJSONArray("rssiHistory");
                JSONArray tsArr = obj.optJSONArray("rssiTimestamps");
                if (rssiArr != null && tsArr != null && rssiArr.length() == tsArr.length()) {
                    for (int j = 0; j < rssiArr.length(); j++) {
                        device.addRssiObservation(rssiArr.getInt(j), tsArr.getLong(j));
                    }
                }

                JSONArray locArr = obj.optJSONArray("targetLocations");
                if (locArr != null) {
                    for (int j = 0; j < locArr.length(); j++) {
                        JSONObject locObj = locArr.getJSONObject(j);
                        device.recordTargetLocation(
                                locObj.getDouble("lat"),
                                locObj.getDouble("lng"),
                                locObj.getLong("ts")
                        );
                    }
                }

                devices.put(mac, device);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error loading device registry from storage: " + e.getMessage());
        }
    }
}