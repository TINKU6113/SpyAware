package com.example.spyaware.model;

public class UserLocationPoint {

    private final long timestamp;
    private final double latitude;
    private final double longitude;

    public UserLocationPoint(
            long timestamp,
            double latitude,
            double longitude
    ) {
        this.timestamp = timestamp;
        this.latitude = latitude;
        this.longitude = longitude;
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
}