package com.example.spyaware.model;

public class KnownDevice {

    private String name;
    private String fingerprint;
    private double referenceRssiAtOneMeter;

    public KnownDevice(
            String name,
            String fingerprint,
            double referenceRssiAtOneMeter) {

        this.name = name;
        this.fingerprint = fingerprint;
        this.referenceRssiAtOneMeter =
                referenceRssiAtOneMeter;
    }

    public String getName() {
        return name;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public double getReferenceRssiAtOneMeter() {
        return referenceRssiAtOneMeter;
    }
}