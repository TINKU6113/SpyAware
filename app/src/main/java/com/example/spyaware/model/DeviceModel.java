package com.example.spyaware.model;
import java.util.ArrayList;
import com.example.spyaware.security.RiskEngine;
import java.util.List;
public class DeviceModel {

    private String deviceName;
    private String macAddress;
    // ============================================================
// DEVICE CLASSIFICATION
// ============================================================

    public static final String CLASS_UNKNOWN = "UNKNOWN";
    public static final String CLASS_KNOWN = "KNOWN";

    private String deviceClassification = CLASS_UNKNOWN;
    private int rssi;
    // RSSI-based distance estimation
    private double estimatedDistance = -1.0;

    // Reference RSSI measured at approximately 1 metre
    private static final double DEFAULT_REFERENCE_RSSI_AT_ONE_METER = -59.0;
    private static final double PATH_LOSS_EXPONENT = 2.0;
    private double referenceRssiAtOneMeter =
            DEFAULT_REFERENCE_RSSI_AT_ONE_METER;

    private boolean calibrated = false;

    private String distanceEstimationMethod =
            "THEORETICAL";

    private String distanceConfidence =
            "LOW";
    private String firstSeen;
    private String lastSeen;
    private long firstSeenTimestamp;
    private long lastSeenTimestamp;


    private int packetCount;

    // BLE advertisement information
    private String manufacturerData;
    private String serviceUuids;
    private int txPower;
    // BLE fingerprint
    private String bleFingerprint = "Unknown";
    // Device classification

    private int riskScore = 0;

    private String riskLevel = RiskEngine.LOW;

    // RSSI history
    private final List<Integer> rssiHistory = new ArrayList<>();
    private final List<Long> rssiTimestamps = new ArrayList<>();

    // Advertisement timing
    private long lastObservationTime = 0;
    private long totalInterval = 0;
    private int intervalCount = 0;
    // Persistence tracking


    // Presence session tracking
    private long currentSessionStart = 0;
    private long currentSessionLastSeen = 0;

    private long totalPresenceTime = 0;

    private int sessionCount = 0;

    private boolean currentlyPresent = false;

    private static final long PRESENCE_TIMEOUT_MS = 10000;
    private int calibrationRssi = Integer.MIN_VALUE;

    public DeviceModel(
            String deviceName,
            String macAddress,
            int rssi,
            String firstSeen,
            String lastSeen
    ) {

        this.deviceName = deviceName;
        this.macAddress = macAddress;

        this.rssi = rssi;

        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
        long now = System.currentTimeMillis();

        this.firstSeenTimestamp = now;
        this.lastSeenTimestamp = now;

        this.packetCount = 1;

        this.manufacturerData = "None";
        this.serviceUuids = "None";
        this.txPower = Integer.MIN_VALUE;
        addRssiObservation(rssi, System.currentTimeMillis());
        updateEstimatedDistance();
    }

    public String getDeviceName() {
        return deviceName;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public int getRssi() {
        return rssi;
    }

    public String getFirstSeen() {
        return firstSeen;
    }

    public String getLastSeen() {
        return lastSeen;
    }

    public int getPacketCount() {
        return packetCount;
    }

    public String getManufacturerData() {
        return manufacturerData;
    }

    public String getServiceUuids() {
        return serviceUuids;
    }

    public int getTxPower() {
        return txPower;
    }
    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {

        if (riskLevel == null ||
                riskLevel.isEmpty()) {

            this.riskLevel = "LOW";

            return;
        }

        this.riskLevel = riskLevel;
    }

    public void updateDevice(
            String deviceName,
            int rssi,
            String lastSeen
    ) {

        if (deviceName != null && !deviceName.isEmpty()) {
            this.deviceName = deviceName;
        }

        this.rssi = rssi;

        this.lastSeen = lastSeen;
        this.lastSeenTimestamp =
                System.currentTimeMillis();

        this.packetCount++;

        addRssiObservation(
                rssi,
                System.currentTimeMillis()
        );

        // Recalculate estimated distance
        updateEstimatedDistance();
    }

    public void setAdvertisementData(
            String manufacturerData,
            String serviceUuids,
            int txPower
    ) {

        if (manufacturerData != null &&
                !manufacturerData.isEmpty()) {

            this.manufacturerData = manufacturerData;
        }

        if (serviceUuids != null &&
                !serviceUuids.isEmpty()) {

            this.serviceUuids = serviceUuids;
        }

        this.txPower = txPower;
    }
    public void addRssiObservation(int rssi, long timestamp) {

        // Keep only the latest 50 RSSI observations
        if (rssiHistory.size() >= 50) {
            rssiHistory.remove(0);
            rssiTimestamps.remove(0);
        }

        rssiHistory.add(rssi);
        rssiTimestamps.add(timestamp);

        // Estimate observation interval
        if (lastObservationTime > 0) {

            long interval =
                    timestamp - lastObservationTime;

            // Ignore unrealistic intervals
            if (interval > 0 && interval < 10000) {

                totalInterval += interval;
                intervalCount++;
            }
        }

        lastObservationTime = timestamp;
    }


    public List<Integer> getRssiHistory() {
        return rssiHistory;
    }


    public double getAverageRssi() {

        if (rssiHistory.isEmpty()) {
            return 0;
        }

        /*
         * Use only the latest 10 RSSI observations.
         * This gives us a smoother but responsive signal.
         */
        int sampleCount =
                Math.min(10, rssiHistory.size());

        int startIndex =
                rssiHistory.size() - sampleCount;

        int sum = 0;

        for (int i = startIndex;
             i < rssiHistory.size();
             i++) {

            sum += rssiHistory.get(i);
        }

        return (double) sum / sampleCount;
    }


    public int getMinimumRssi() {

        if (rssiHistory.isEmpty()) {
            return 0;
        }

        int min = rssiHistory.get(0);

        for (int value : rssiHistory) {
            if (value < min) {
                min = value;
            }
        }

        return min;
    }


    public int getMaximumRssi() {

        if (rssiHistory.isEmpty()) {
            return 0;
        }

        int max = rssiHistory.get(0);

        for (int value : rssiHistory) {
            if (value > max) {
                max = value;
            }
        }

        return max;
    }


    public double getAverageIntervalMs() {

        if (intervalCount == 0) {
            return 0;
        }

        return (double) totalInterval / intervalCount;
    }
    public void setBleFingerprint(String fingerprint) {

        if (fingerprint != null &&
                !fingerprint.isEmpty()) {

            this.bleFingerprint = fingerprint;
        }
    }



    public String getBleFingerprint() {
        return bleFingerprint;
    }
    // ============================================================
// DEVICE CLASSIFICATION
// ============================================================

    public String getDeviceClassification() {

        return deviceClassification;
    }

    public void setDeviceClassification(
            String classification) {

        if (classification == null ||
                classification.isEmpty()) {

            deviceClassification = CLASS_UNKNOWN;

            return;
        }

        deviceClassification = classification;
    }

    public boolean isKnownDevice() {

        return CLASS_KNOWN.equals(
                deviceClassification
        );
    }

    public boolean isUnknownDevice() {

        return CLASS_UNKNOWN.equals(
                deviceClassification
        );
    }

    public void classifyDevice(
            KnownDeviceRegistry registry) {

        // No registry available
        if (registry == null) {

            deviceClassification =
                    CLASS_UNKNOWN;

            return;
        }

        // No usable fingerprint
        if (bleFingerprint == null ||
                bleFingerprint.equals("Unknown") ||
                bleFingerprint.isEmpty()) {

            deviceClassification =
                    CLASS_UNKNOWN;

            return;
        }

        // Search for the fingerprint
        KnownDevice knownDevice =
                registry.findByFingerprint(
                        bleFingerprint
                );

        if (knownDevice != null) {

            // Fingerprint matched
            deviceClassification =
                    CLASS_KNOWN;

            // Restore calibration
            setReferenceRssiAtOneMeter(
                    knownDevice
                            .getReferenceRssiAtOneMeter()
            );

        } else {

            // Fingerprint not found
            deviceClassification =
                    CLASS_UNKNOWN;
        }
    }
    public String getProximityState() {

        if (rssiHistory.isEmpty()) {
            return "UNKNOWN";
        }

        double average = getAverageRssi();

        if (average >= -60) {
            return "VERY NEAR";
        } else if (average >= -75) {
            return "NEAR";
        } else if (average >= -90) {
            return "MEDIUM";
        } else {
            return "FAR";
        }
    }
    public long getObservationDurationMs() {

        return lastSeenTimestamp - firstSeenTimestamp;
    }

    public String getObservationDurationFormatted() {

        long duration = getObservationDurationMs();

        long seconds = duration / 1000;

        long hours = seconds / 3600;

        long minutes = (seconds % 3600) / 60;

        long remainingSeconds = seconds % 60;

        if (hours > 0) {

            return hours + "h "
                    + minutes + "m "
                    + remainingSeconds + "s";

        } else if (minutes > 0) {

            return minutes + "m "
                    + remainingSeconds + "s";

        } else {

            return remainingSeconds + "s";
        }
    }

    public String getPersistenceState() {

        long duration = getObservationDurationMs();

        if (packetCount < 5 && duration < 10000) {
            return "SHORT";
        }

        if (packetCount >= 5 && duration >= 10000) {

            if (duration >= 60000) {
                return "PERSISTENT";
            }

            return "RECURRING";
        }

        return "OCCASIONAL";
    }
    public void recordPresence(long timestamp) {

        if (!currentlyPresent) {

            // Device was previously absent
            // Start a new presence session

            currentSessionStart = timestamp;
            currentSessionLastSeen = timestamp;

            sessionCount++;

            currentlyPresent = true;

            return;
        }

        // Device is already inside a session

        currentSessionLastSeen = timestamp;
    }
    public void checkPresenceTimeout(long currentTime) {

        if (!currentlyPresent) {
            return;
        }

        long timeSinceLastSeen =
                currentTime - currentSessionLastSeen;

        if (timeSinceLastSeen > PRESENCE_TIMEOUT_MS) {

            totalPresenceTime +=
                    currentSessionLastSeen - currentSessionStart;

            currentlyPresent = false;
        }
    }
    public long getTotalPresenceTimeMs() {

        long total = totalPresenceTime;

        // Include the active session
        if (currentlyPresent) {

            total +=
                    currentSessionLastSeen
                            - currentSessionStart;
        }

        return total;
    }

    public String getTotalPresenceFormatted() {

        long duration =
                getTotalPresenceTimeMs();

        long seconds = duration / 1000;

        long hours = seconds / 3600;

        long minutes = (seconds % 3600) / 60;

        long remainingSeconds = seconds % 60;

        if (hours > 0) {

            return hours + "h "
                    + minutes + "m "
                    + remainingSeconds + "s";

        } else if (minutes > 0) {

            return minutes + "m "
                    + remainingSeconds + "s";

        } else {

            return remainingSeconds + "s";
        }
    }
    public int getSessionCount() {
        return sessionCount;
    }
    public boolean isCurrentlyPresent() {
        return currentlyPresent;
    }

    public void updateEstimatedDistance() {

        if (rssiHistory.isEmpty()) {
            estimatedDistance = -1.0;
            return;
        }

        /*
         * Use smoothed RSSI instead of one instantaneous RSSI.
         * This prevents the estimated distance from jumping
         * heavily due to normal BLE RSSI fluctuations.
         */
        double measuredRssi = getAverageRssi();

        /*
         * RSSI path-loss model:
         *
         * d = 10 ^ ((RSSI_1m - RSSI) / (10 * n))
         *
         * RSSI_1m:
         *   Calibrated device -> measured reference
         *   Unknown device    -> theoretical -59 dBm
         *
         * n:
         *   2.0 = reasonable starting value for open space
         */
        estimatedDistance =
                Math.pow(
                        10,
                        (referenceRssiAtOneMeter - measuredRssi)
                                / (10 * PATH_LOSS_EXPONENT)
                );

        /*
         * Determine how the estimate was produced.
         */
        if (calibrated) {

            distanceEstimationMethod =
                    "CALIBRATED";

        } else {

            distanceEstimationMethod =
                    "THEORETICAL";
        }

        /*
         * Determine confidence.
         */
        updateDistanceConfidence();
    }
    private void updateDistanceConfidence() {

        int sampleCount =
                rssiHistory.size();

        if (!calibrated) {

            /*
             * Unknown devices always start with
             * lower confidence because the RSSI
             * reference is theoretical.
             */

            if (sampleCount >= 20) {

                distanceConfidence = "MEDIUM";

            } else {

                distanceConfidence = "LOW";
            }

            return;
        }


        /*
         * Calibrated device.
         *
         * More observations give us a more stable
         * RSSI estimate.
         */

        if (sampleCount >= 20) {

            distanceConfidence = "HIGH";

        } else if (sampleCount >= 10) {

            distanceConfidence = "MEDIUM";

        } else {

            distanceConfidence = "LOW";
        }
    }
    public String getDistanceEstimationMethod() {
        return distanceEstimationMethod;
    }

    public String getDistanceConfidence() {
        return distanceConfidence;
    }
    public double getEstimatedDistance() {
        return estimatedDistance;
    }
    public void setReferenceRssiAtOneMeter(double referenceRssi) {

        this.referenceRssiAtOneMeter = referenceRssi;

        // Recalculate using the new calibration value
        updateEstimatedDistance();
    }
    public double getReferenceRssiAtOneMeter() {
        return referenceRssiAtOneMeter;
    }
    public String getRssiTrend() {

        // We need several observations before
        // attempting to determine movement.
        if (rssiHistory.size() < 5) {
            return "INSUFFICIENT DATA";
        }

        // Look at the latest 5 RSSI observations.
        int size = rssiHistory.size();

        int oldest = rssiHistory.get(size - 5);
        int newest = rssiHistory.get(size - 1);

        int difference = newest - oldest;

        /*
         * RSSI becomes less negative when signal gets stronger.
         *
         * Example:
         * -85 → -70
         *
         * difference = +15
         * signal became stronger
         *
         * Therefore:
         * positive difference → approaching
         * negative difference → moving away
         */

        if (difference >= 6) {
            return "APPROACHING";
        }

        if (difference <= -6) {
            return "MOVING AWAY";
        }

        return "STABLE";
    }
    public void calibrateAtOneMeter() {

        if (rssiHistory.isEmpty()) {
            return;
        }

        /*
         * Use the recent RSSI observations rather than
         * relying on a single noisy measurement.
         */

        int sampleCount = Math.min(10, rssiHistory.size());

        int startIndex =
                rssiHistory.size() - sampleCount;

        int sum = 0;

        for (int i = startIndex;
             i < rssiHistory.size();
             i++) {

            sum += rssiHistory.get(i);
        }

        double average =
                (double) sum / sampleCount;

        referenceRssiAtOneMeter = average;

        calibrated = true;

        // Recalculate distance using the new reference.
        updateEstimatedDistance();
    }
    public boolean isCalibrated() {
        return calibrated;
    }
    public void setCalibrationRssi(int rssi) {

        this.calibrationRssi = rssi;

        this.referenceRssiAtOneMeter =
                (double) rssi;

        this.calibrated = true;

        updateEstimatedDistance();
    }

    public int getCalibrationRssi() {

        return calibrationRssi;
    }

    public long getObservationDurationSeconds() {

        return getObservationDurationMs() / 1000;
    }
    public String getObservationDurationText() {

        long totalSeconds =
                getObservationDurationSeconds();

        long hours =
                totalSeconds / 3600;

        long minutes =
                (totalSeconds % 3600) / 60;

        long seconds =
                totalSeconds % 60;

        if (hours > 0) {

            return hours + "h "
                    + minutes + "m "
                    + seconds + "s";

        } else if (minutes > 0) {

            return minutes + "m "
                    + seconds + "s";

        } else {

            return seconds + "s";
        }
    }
    public void updateRiskAssessment() {

        int score =
                com.example.spyaware.security.RiskEngine
                        .calculateRiskScore(this);

        String level =
                com.example.spyaware.security.RiskEngine
                        .getRiskLevel(score);

        this.riskScore = score;

        this.riskLevel = level;
    }

}