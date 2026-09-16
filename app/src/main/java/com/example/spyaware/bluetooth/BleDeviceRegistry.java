package com.example.spyaware.bluetooth;

import com.example.spyaware.model.DeviceModel;

import java.util.LinkedHashMap;
import java.util.Map;

public class BleDeviceRegistry {

    private static final Map<String, DeviceModel> devices =
            new LinkedHashMap<>();

    private BleDeviceRegistry() {
        // Prevent accidental object creation
    }

    public static void addDevice(
            String identifier,
            DeviceModel device) {

        devices.put(identifier, device);
    }

    public static DeviceModel getDevice(
            String identifier) {

        return devices.get(identifier);
    }

    public static Map<String, DeviceModel> getDevices() {

        return devices;
    }

    public static boolean contains(
            String identifier) {

        return devices.containsKey(identifier);
    }
}