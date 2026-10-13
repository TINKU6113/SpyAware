package com.example.spyaware.model;

public class TargetLocationPoint {

    private final long timestamp;
    private final double latitude;
    private final double longitude;
    private final double estimatedDistance;
    private final int rssi;
    private final String rssiTrend;
    private final String distanceConfidence;

    public TargetLocationPoint(
            long timestamp,
            double latitude,
            double longitude,
            double estimatedDistance,
            int rssi,
            String rssiTrend,
            String distanceConfidence
    ) {
        this.timestamp = timestamp;
        this.latitude = latitude;
        this.longitude = longitude;
        this.estimatedDistance = estimatedDistance;
        this.rssi = rssi;
        this.rssiTrend = rssiTrend;
        this.distanceConfidence = distanceConfidence;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public double getLatitude() {
        return latitude;
    }

    public double getLongitude() {
        return longitude;
    }

    public double getEstimatedDistance() {
        return estimatedDistance;
    }

    public int getRssi() {
        return rssi;
    }

    public String getRssiTrend() {
        return rssiTrend;
    }

    public String getDistanceConfidence() {
        return distanceConfidence;
    }
}