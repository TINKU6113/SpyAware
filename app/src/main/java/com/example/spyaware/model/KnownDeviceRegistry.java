package com.example.spyaware.model;

import java.util.ArrayList;
import java.util.List;

public class KnownDeviceRegistry {

    private static KnownDeviceRegistry instance;

    private final List<KnownDevice> knownDevices =
            new ArrayList<>();

    private KnownDeviceRegistry() {
    }

    public static synchronized KnownDeviceRegistry getInstance() {

        if (instance == null) {
            instance = new KnownDeviceRegistry();
        }

        return instance;
    }

    public void addKnownDevice(KnownDevice device) {

        if (device == null) {
            return;
        }

        if (findByFingerprint(
                device.getFingerprint()) != null) {

            return;
        }

        knownDevices.add(device);
    }

    public boolean removeByFingerprint(
            String fingerprint) {

        if (fingerprint == null ||
                fingerprint.isEmpty()) {

            return false;
        }

        KnownDevice device =
                findByFingerprint(fingerprint);

        if (device == null) {
            return false;
        }

        return knownDevices.remove(device);
    }

    public KnownDevice findByFingerprint(
            String fingerprint) {

        if (fingerprint == null ||
                fingerprint.isEmpty() ||
                fingerprint.equals("Unknown")) {

            return null;
        }

        for (KnownDevice device : knownDevices) {

            if (fingerprint.equals(
                    device.getFingerprint())) {

                return device;
            }
        }

        return null;
    }

    public boolean isKnown(String fingerprint) {

        return findByFingerprint(fingerprint) != null;
    }

    public List<KnownDevice> getKnownDevices() {

        return knownDevices;
    }
}