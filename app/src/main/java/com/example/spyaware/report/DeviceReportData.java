package com.example.spyaware.report;

import android.graphics.Bitmap;

import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.model.TargetLocationPoint;
import com.example.spyaware.model.UserLocationPoint;
import com.example.spyaware.security.RiskEngine;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Encapsulates all data required to generate an investigative report
 * for a specific BLE device detected by SpyAware.
 */
public class DeviceReportData {

    // --- Report Metadata ---
    private final String reportId;
    private final long generationTimestamp;
    private final String generationTimestampFormatted;
    private final String deviceIdentifier;
    private final String reportVersion = "1.0";

    // --- Device Identity ---
    private final String deviceName;
    private final String macAddress;
    private final String manufacturerInfo;
    private final String resolvedManufacturer;
    private final String serviceUuids;
    private final int txPower;
    private final String bleFingerprint;
    private final String classification;
    private final String identityConfidence;

    // --- Observation History ---
    private final long firstObservedTimestamp;
    private final String firstObservedFormatted;
    private final long lastObservedTimestamp;
    private final String lastObservedFormatted;
    private final long elapsedWindowMs;
    private final String elapsedWindowFormatted;
    private final long activePresenceDurationMs;
    private final String activePresenceDurationFormatted;
    private final int packetCount;
    private final int sessionCount;
    private final boolean currentlyPresent;
    private final String persistenceState;
    private final double averageIntervalMs;
    private final long longestGapMs;
    private final String longestGapFormatted;
    private final int observationGapsCount;
    private final List<DeviceModel.ObservationSession> sessions;

    // --- BLE Signal Analysis ---
    private final List<Integer> rssiHistory;
    private final List<Long> rssiTimestamps;
    private final int latestRssi;
    private final double averageRssi;
    private final int minRssi;
    private final int maxRssi;
    private final String rssiTrend;
    private final double currentEstimatedDistance;
    private final double minEstimatedDistance;
    private final double maxEstimatedDistance;
    private final double avgEstimatedDistance;
    private final String distanceEstimationMethod;
    private final String distanceConfidence;
    private final double referenceRssiAtOneMeter;
    private final boolean isCalibrated;
    private final String proximityState;

    // --- Behavioural Analysis ---
    private final int riskScore;
    private final String riskLevel;
    private final Map<String, Integer> scoreComponents;
    private final List<String> flaggedEvidence;
    private final List<FactInferencePair> factsVsInferences;
    private final List<String> recommendedNextSteps;

    // --- Geospatial History ---
    private final List<UserLocationPoint> userLocationPoints;
    private final List<TargetLocationPoint> targetLocationPoints;
    private final String locationDisclosure;
    private Bitmap mapSnapshotBitmap;
    private String mapSnapshotStatus;

    public DeviceReportData(
            String reportId,
            long generationTimestamp,
            String deviceIdentifier,
            String deviceName,
            String macAddress,
            String manufacturerInfo,
            String resolvedManufacturer,
            String serviceUuids,
            int txPower,
            String bleFingerprint,
            String classification,
            String identityConfidence,
            long firstObservedTimestamp,
            long lastObservedTimestamp,
            long activePresenceDurationMs,
            int packetCount,
            int sessionCount,
            boolean currentlyPresent,
            String persistenceState,
            double averageIntervalMs,
            long longestGapMs,
            int observationGapsCount,
            List<DeviceModel.ObservationSession> sessions,
            List<Integer> rssiHistory,
            List<Long> rssiTimestamps,
            int latestRssi,
            double averageRssi,
            int minRssi,
            int maxRssi,
            String rssiTrend,
            double currentEstimatedDistance,
            double minEstimatedDistance,
            double maxEstimatedDistance,
            double avgEstimatedDistance,
            String distanceEstimationMethod,
            String distanceConfidence,
            double referenceRssiAtOneMeter,
            boolean isCalibrated,
            String proximityState,
            int riskScore,
            String riskLevel,
            Map<String, Integer> scoreComponents,
            List<String> flaggedEvidence,
            List<FactInferencePair> factsVsInferences,
            List<String> recommendedNextSteps,
            List<UserLocationPoint> userLocationPoints,
            List<TargetLocationPoint> targetLocationPoints,
            String locationDisclosure,
            Bitmap mapSnapshotBitmap,
            String mapSnapshotStatus
    ) {
        this.reportId = reportId;
        this.generationTimestamp = generationTimestamp;
        this.generationTimestampFormatted = formatDateTime(generationTimestamp);
        this.deviceIdentifier = deviceIdentifier;
        this.deviceName = deviceName;
        this.macAddress = macAddress;
        this.manufacturerInfo = manufacturerInfo;
        this.resolvedManufacturer = resolvedManufacturer;
        this.serviceUuids = serviceUuids;
        this.txPower = txPower;
        this.bleFingerprint = bleFingerprint;
        this.classification = classification;
        this.identityConfidence = identityConfidence;
        this.firstObservedTimestamp = firstObservedTimestamp;
        this.firstObservedFormatted = formatDateTime(firstObservedTimestamp);
        this.lastObservedTimestamp = lastObservedTimestamp;
        this.lastObservedFormatted = formatDateTime(lastObservedTimestamp);
        this.elapsedWindowMs = Math.max(0, lastObservedTimestamp - firstObservedTimestamp);
        this.elapsedWindowFormatted = formatDuration(this.elapsedWindowMs);
        this.activePresenceDurationMs = activePresenceDurationMs;
        this.activePresenceDurationFormatted = formatDuration(activePresenceDurationMs);
        this.packetCount = packetCount;
        this.sessionCount = sessionCount;
        this.currentlyPresent = currentlyPresent;
        this.persistenceState = persistenceState;
        this.averageIntervalMs = averageIntervalMs;
        this.longestGapMs = longestGapMs;
        this.longestGapFormatted = formatDuration(longestGapMs);
        this.observationGapsCount = observationGapsCount;
        this.sessions = sessions != null ? Collections.unmodifiableList(sessions) : Collections.emptyList();
        this.rssiHistory = rssiHistory != null ? Collections.unmodifiableList(rssiHistory) : Collections.emptyList();
        this.rssiTimestamps = rssiTimestamps != null ? Collections.unmodifiableList(rssiTimestamps) : Collections.emptyList();
        this.latestRssi = latestRssi;
        this.averageRssi = averageRssi;
        this.minRssi = minRssi;
        this.maxRssi = maxRssi;
        this.rssiTrend = rssiTrend;
        this.currentEstimatedDistance = currentEstimatedDistance;
        this.minEstimatedDistance = minEstimatedDistance;
        this.maxEstimatedDistance = maxEstimatedDistance;
        this.avgEstimatedDistance = avgEstimatedDistance;
        this.distanceEstimationMethod = distanceEstimationMethod;
        this.distanceConfidence = distanceConfidence;
        this.referenceRssiAtOneMeter = referenceRssiAtOneMeter;
        this.isCalibrated = isCalibrated;
        this.proximityState = proximityState;
        this.riskScore = riskScore;
        this.riskLevel = riskLevel;
        this.scoreComponents = scoreComponents != null ? Collections.unmodifiableMap(scoreComponents) : Collections.emptyMap();
        this.flaggedEvidence = flaggedEvidence != null ? Collections.unmodifiableList(flaggedEvidence) : Collections.emptyList();
        this.factsVsInferences = factsVsInferences != null ? Collections.unmodifiableList(factsVsInferences) : Collections.emptyList();
        this.recommendedNextSteps = recommendedNextSteps != null ? Collections.unmodifiableList(recommendedNextSteps) : Collections.emptyList();
        this.userLocationPoints = userLocationPoints != null ? Collections.unmodifiableList(userLocationPoints) : Collections.emptyList();
        this.targetLocationPoints = targetLocationPoints != null ? Collections.unmodifiableList(targetLocationPoints) : Collections.emptyList();
        this.locationDisclosure = locationDisclosure;
        this.mapSnapshotBitmap = mapSnapshotBitmap;
        this.mapSnapshotStatus = mapSnapshotStatus;
    }

    /**
     * Factory method compiling complete report data from a live DeviceModel
     * and investigator phone location history.
     */
    public static DeviceReportData fromDeviceModel(DeviceModel device, List<UserLocationPoint> userLocations) {
        if (device == null) {
            throw new IllegalArgumentException("DeviceModel cannot be null");
        }

        long now = System.currentTimeMillis();
        String reportId = "REP-" + new SimpleDateFormat("yyyyMMdd", Locale.US).format(new Date(now))
                + "-" + UUID.randomUUID().toString().substring(0, 6).toUpperCase(Locale.US);

        String id = device.getMacAddress();
        if (id == null || id.isEmpty()) {
            id = device.getBleFingerprint();
        }

        String name = device.getDeviceName();
        if (name == null || name.trim().isEmpty() || "Unknown BLE Device".equalsIgnoreCase(name)) {
            name = "Unknown BLE Device";
        }

        String mac = device.getMacAddress() != null && !device.getMacAddress().isEmpty()
                ? device.getMacAddress() : "Not Disclosed / Random RPA";

        String mfgData = device.getManufacturerData() != null ? device.getManufacturerData() : "None";
        String resolvedMfg = resolveManufacturerName(mfgData);

        String services = device.getServiceUuids() != null ? device.getServiceUuids() : "None";
        int tx = device.getTxPower();

        String fingerprint = device.getBleFingerprint() != null ? device.getBleFingerprint() : "Unknown";
        String classification = device.getDeviceClassification();

        String identityConf = "BLE addresses are subject to periodic randomization via Bluetooth Resolvable Private Addresses (RPA). "
                + "Device identity is established through multi-attribute payload fingerprinting (SHA-256) rather than static MAC alone.";

        long firstSeen = device.getFirstSeenTimestamp();
        long lastSeen = device.getLastSeenTimestamp();
        if (firstSeen <= 0) firstSeen = now;
        if (lastSeen < firstSeen) lastSeen = firstSeen;

        long activePresence = device.getTotalPresenceTimeMs();
        List<Integer> rssiHistory = new ArrayList<>(device.getRssiHistory());
        int packetCount = Math.max(Math.max(1, device.getPacketCount()), rssiHistory.size());
        int sessionCount = Math.max(1, device.getSessionCount());
        boolean isPresent = device.isCurrentlyPresent();
        String persistence = device.getPersistenceState();
        double avgInterval = device.getAverageIntervalMs();

        List<DeviceModel.ObservationSession> sessions = device.getAllSessions();

        // Calculate gaps between observations
        List<Long> timestamps = new ArrayList<>(device.getRssiTimestamps());
        long longestGap = 0;
        int gapCount = 0;
        if (timestamps.size() >= 2) {
            for (int i = 1; i < timestamps.size(); i++) {
                long gap = timestamps.get(i) - timestamps.get(i - 1);
                if (gap > 10000) { // Gaps exceeding presence timeout (10s)
                    gapCount++;
                    if (gap > longestGap) {
                        longestGap = gap;
                    }
                }
            }
        }
        int latestRssi = device.getLatestRssi();
        double avgRssi = device.getAverageRssi();
        int minRssi = device.getMinimumRssi();
        int maxRssi = device.getMaximumRssi();
        String trend = device.getRssiTrend();

        double currentDist = device.getEstimatedDistance();
        double minDist = currentDist;
        double maxDist = currentDist;
        double sumDist = 0;
        int validDistCount = 0;

        for (int r : rssiHistory) {
            double d = Math.pow(10, (device.getReferenceRssiAtOneMeter() - r) / (10 * 2.0));
            sumDist += d;
            validDistCount++;
            if (minDist < 0 || d < minDist) minDist = d;
            if (d > maxDist) maxDist = d;
        }
        double avgDist = validDistCount > 0 ? (sumDist / validDistCount) : currentDist;

        String distMethod = device.getDistanceEstimationMethod();
        String distConf = device.getDistanceConfidence();
        double refRssi = device.getReferenceRssiAtOneMeter();
        boolean calibrated = device.isCalibrated();
        String proximity = device.getProximityState();

        device.updateRiskAssessment();
        int riskScore = device.getRiskScore();
        String riskLevel = device.getRiskLevel();

        // Breakdown of RiskEngine components
        Map<String, Integer> scoreComponents = new HashMap<>();
        if (device.isUnknownDevice()) {
            scoreComponents.put("Classification: Unknown Device", 10);
        } else if (device.isKnownDevice()) {
            scoreComponents.put("Classification: Registered Known Device", -20);
        }

        if (currentDist >= 0) {
            if (currentDist < 1) {
                scoreComponents.put("Proximity: Very Close (<1m)", 25);
            } else if (currentDist < 2) {
                scoreComponents.put("Proximity: Close (<2m)", 18);
            } else if (currentDist < 5) {
                scoreComponents.put("Proximity: Moderate (<5m)", 12);
            } else if (currentDist < 10) {
                scoreComponents.put("Proximity: Extended (<10m)", 7);
            } else if (currentDist < 15) {
                scoreComponents.put("Proximity: Distant (<15m)", 3);
            }
        }

        if ("PERSISTENT".equals(persistence)) {
            scoreComponents.put("Persistence: Sustained Presence", 20);
        } else if ("RECURRING".equals(persistence)) {
            scoreComponents.put("Persistence: Recurring Signal", 10);
        } else if ("OCCASIONAL".equals(persistence)) {
            scoreComponents.put("Persistence: Occasional Signal", 5);
        }

        if ("APPROACHING".equals(trend)) {
            scoreComponents.put("Signal Trend: Approaching Investigator", 15);
        } else if ("STABLE".equals(trend)) {
            scoreComponents.put("Signal Trend: Stable Distance", 3);
        }

        if (sessionCount >= 4) {
            scoreComponents.put("Repeated Sessions: High Count (>=4)", 10);
        } else if (sessionCount >= 2) {
            scoreComponents.put("Repeated Sessions: Multiple (>=2)", 5);
        }

        // Flagged specific evidence
        List<String> evidence = new ArrayList<>();
        if (RiskEngine.CRITICAL.equals(riskLevel) || RiskEngine.HIGH.equals(riskLevel)) {
            evidence.add("Risk assessment threshold (" + riskScore + "/100) exceeded High/Critical safety boundary.");
        }
        if (currentDist >= 0 && currentDist < 3.0) {
            evidence.add(String.format(Locale.US, "Close estimated proximity observed (current %.1fm, min %.1fm).", currentDist, minDist));
        }
        if ("PERSISTENT".equals(persistence) || "RECURRING".equals(persistence)) {
            evidence.add("Device exhibited repeated/persistent presence over " + formatDuration(lastSeen - firstSeen) + " observation window.");
        }
        if ("APPROACHING".equals(trend)) {
            evidence.add("RSSI differential indicates signal strength increased steadily (+6 dBm delta), consistent with approaching orientation.");
        }
        if (sessionCount >= 3) {
            evidence.add("Device recorded across " + sessionCount + " distinct presence sessions with intermittent re-appearance.");
        }
        if (evidence.isEmpty()) {
            evidence.add("Standard BLE emissions observed without anomalous persistence or approach patterns.");
        }

        // Facts vs Inferences
        List<FactInferencePair> factsVsInferences = new ArrayList<>();
        factsVsInferences.add(new FactInferencePair(
                "Received " + packetCount + " BLE advertising packets at " + latestRssi + " dBm",
                "Estimated distance is approx. " + (currentDist >= 0 ? String.format(Locale.US, "%.1fm", currentDist) : "Unavailable") + " (log-distance path loss, n=2.0)"
        ));
        factsVsInferences.add(new FactInferencePair(
                "Observed between " + formatDateTime(firstSeen) + " and " + formatDateTime(lastSeen),
                "Classification as '" + persistence + "' persistence based on observation duration & packet frequency"
        ));
        factsVsInferences.add(new FactInferencePair(
                "Observed across " + sessionCount + " presence sessions (total active presence " + formatDuration(activePresence) + ")",
                "Device inferred to have moved out of range or ceased broadcast during unobserved intervals"
        ));
        factsVsInferences.add(new FactInferencePair(
                "Payload advertising fingerprint: " + (fingerprint.length() > 16 ? fingerprint.substring(0, 16) + "..." : fingerprint),
                "Identification as " + (device.isKnownDevice() ? "USER-TRUSTED" : "UNREGISTERED") + " device based on local known-device registry"
        ));

        // Suggested next steps
        List<String> nextSteps = new ArrayList<>();
        if (RiskEngine.CRITICAL.equals(riskLevel) || RiskEngine.HIGH.equals(riskLevel)) {
            nextSteps.add("Conduct a systematic physical inspection of personal belongings, vehicle exterior/wheel-wells, and baggage.");
            nextSteps.add("Move to an alternate physical location (e.g. 100-200 meters away) and re-scan to evaluate co-movement correlation.");
            nextSteps.add("Inspect nearby known companion devices (smartwatches, audio accessories, personal tags) to rule out false positives.");
            nextSteps.add("If persistence continues across multiple separate geographical waypoints, retain this report as forensic evidence.");
        } else {
            nextSteps.add("Register device as 'Known' if this is an expected personal or family accessory.");
            nextSteps.add("Monitor ambient BLE environment periodically in high-risk locations.");
            nextSteps.add("No immediate evasion or physical sweep required based on current low risk scoring.");
        }

        List<TargetLocationPoint> targetLocations = new ArrayList<>(device.getTargetLocationHistory());
        List<UserLocationPoint> userPoints = userLocations != null ? new ArrayList<>(userLocations) : new ArrayList<>();

        String locDisclosure = "LOCATION SEMANTICS & PRIVACY DISCLOSURE: Recorded GPS coordinates represent the geographical position of the investigator's smartphone (the BLE receiver). BLE signals are omnidirectional; a single receiver cannot determine bearing or physical elevation. Distance is mathematically inferred via RF path loss and should be treated as an approximate proximity boundary, not a confirmed physical location.";

        String mapStatus = "No active map snapshot captured. Target location points recorded: " + targetLocations.size();

        return new DeviceReportData(
                reportId,
                now,
                id,
                name,
                mac,
                mfgData,
                resolvedMfg,
                services,
                tx,
                fingerprint,
                classification,
                identityConf,
                firstSeen,
                lastSeen,
                activePresence,
                packetCount,
                sessionCount,
                isPresent,
                persistence,
                avgInterval,
                longestGap,
                gapCount,
                sessions,
                rssiHistory,
                timestamps,
                latestRssi,
                avgRssi,
                minRssi,
                maxRssi,
                trend,
                currentDist,
                minDist,
                maxDist,
                avgDist,
                distMethod,
                distConf,
                refRssi,
                calibrated,
                proximity,
                riskScore,
                riskLevel,
                scoreComponents,
                evidence,
                factsVsInferences,
                nextSteps,
                userPoints,
                targetLocations,
                locDisclosure,
                null,
                mapStatus
        );
    }

    private static String resolveManufacturerName(String mfgData) {
        if (mfgData == null || mfgData.isEmpty() || "None".equalsIgnoreCase(mfgData)) {
            return "None Reported";
        }
        String lower = mfgData.toLowerCase(Locale.US);
        if (lower.contains("0x004c") || lower.contains("id=0x004c")) {
            return "Apple, Inc. (Find My / AirTag ecosystem)";
        } else if (lower.contains("0x0006") || lower.contains("id=0x0006")) {
            return "Microsoft Corporation";
        } else if (lower.contains("0x0075") || lower.contains("id=0x0075")) {
            return "Samsung Electronics (SmartTag ecosystem)";
        } else if (lower.contains("0x00e0") || lower.contains("id=0x00e0")) {
            return "Google LLC (Find My Device network)";
        } else if (lower.contains("0x038f") || lower.contains("id=0x038f")) {
            return "Tile, Inc. (Tile Tracker)";
        } else if (lower.contains("0x0606") || lower.contains("id=0x0606")) {
            return "Chipolo d.o.o. (Chipolo Tracker)";
        } else if (lower.contains("0x0087") || lower.contains("id=0x0087")) {
            return "Garmin International";
        } else if (lower.contains("0x0157") || lower.contains("id=0x0157")) {
            return "Anhui Huami / Zepp (Xiaomi / Amazfit)";
        } else if (lower.contains("0x0059") || lower.contains("id=0x0059")) {
            return "Nordic Semiconductor";
        }
        return "Manufacturer Data Present (" + (mfgData.length() > 30 ? mfgData.substring(0, 30) + "..." : mfgData) + ")";
    }

    private static String formatDateTime(long ms) {
        if (ms <= 0) return "--";
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date(ms));
    }

    private static String formatDuration(long ms) {
        if (ms <= 0) return "0s";
        long seconds = ms / 1000;
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        long remainingSec = seconds % 60;
        if (hours > 0) {
            return hours + "h " + minutes + "m " + remainingSec + "s";
        } else if (minutes > 0) {
            return minutes + "m " + remainingSec + "s";
        } else {
            return remainingSec + "s";
        }
    }

    public static class FactInferencePair {
        private final String measuredFact;
        private final String algorithmicInference;

        public FactInferencePair(String measuredFact, String algorithmicInference) {
            this.measuredFact = measuredFact;
            this.algorithmicInference = algorithmicInference;
        }

        public String getMeasuredFact() {
            return measuredFact;
        }

        public String getAlgorithmicInference() {
            return algorithmicInference;
        }
    }

    // --- Getters ---
    public String getReportId() { return reportId; }
    public long getGenerationTimestamp() { return generationTimestamp; }
    public String getGenerationTimestampFormatted() { return generationTimestampFormatted; }
    public String getDeviceIdentifier() { return deviceIdentifier; }
    public String getReportVersion() { return reportVersion; }
    public String getDeviceName() { return deviceName; }
    public String getMacAddress() { return macAddress; }
    public String getManufacturerInfo() { return manufacturerInfo; }
    public String getResolvedManufacturer() { return resolvedManufacturer; }
    public String getServiceUuids() { return serviceUuids; }
    public int getTxPower() { return txPower; }
    public String getBleFingerprint() { return bleFingerprint; }
    public String getClassification() { return classification; }
    public String getIdentityConfidence() { return identityConfidence; }
    public long getFirstObservedTimestamp() { return firstObservedTimestamp; }
    public String getFirstObservedFormatted() { return firstObservedFormatted; }
    public long getLastObservedTimestamp() { return lastObservedTimestamp; }
    public String getLastObservedFormatted() { return lastObservedFormatted; }
    public long getElapsedWindowMs() { return elapsedWindowMs; }
    public String getElapsedWindowFormatted() { return elapsedWindowFormatted; }
    public long getActivePresenceDurationMs() { return activePresenceDurationMs; }
    public String getActivePresenceDurationFormatted() { return activePresenceDurationFormatted; }
    public int getPacketCount() { return packetCount; }
    public int getSessionCount() { return sessionCount; }
    public boolean isCurrentlyPresent() { return currentlyPresent; }
    public String getPersistenceState() { return persistenceState; }
    public double getAverageIntervalMs() { return averageIntervalMs; }
    public long getLongestGapMs() { return longestGapMs; }
    public String getLongestGapFormatted() { return longestGapFormatted; }
    public int getObservationGapsCount() { return observationGapsCount; }
    public List<DeviceModel.ObservationSession> getSessions() { return sessions; }
    public List<Integer> getRssiHistory() { return rssiHistory; }
    public List<Long> getRssiTimestamps() { return rssiTimestamps; }
    public int getLatestRssi() { return latestRssi; }
    public double getAverageRssi() { return averageRssi; }
    public int getMinRssi() { return minRssi; }
    public int getMaxRssi() { return maxRssi; }
    public String getRssiTrend() { return rssiTrend; }
    public double getCurrentEstimatedDistance() { return currentEstimatedDistance; }
    public double getMinEstimatedDistance() { return minEstimatedDistance; }
    public double getMaxEstimatedDistance() { return maxEstimatedDistance; }
    public double getAvgEstimatedDistance() { return avgEstimatedDistance; }
    public String getDistanceEstimationMethod() { return distanceEstimationMethod; }
    public String getDistanceConfidence() { return distanceConfidence; }
    public double getReferenceRssiAtOneMeter() { return referenceRssiAtOneMeter; }
    public boolean isCalibrated() { return isCalibrated; }
    public String getProximityState() { return proximityState; }
    public int getRiskScore() { return riskScore; }
    public String getRiskLevel() { return riskLevel; }
    public Map<String, Integer> scoreComponents() { return scoreComponents; }
    public List<String> getFlaggedEvidence() { return flaggedEvidence; }
    public List<FactInferencePair> getFactsVsInferences() { return factsVsInferences; }
    public List<String> getRecommendedNextSteps() { return recommendedNextSteps; }
    public List<UserLocationPoint> getUserLocationPoints() { return userLocationPoints; }
    public List<TargetLocationPoint> getTargetLocationPoints() { return targetLocationPoints; }
    public String getLocationDisclosure() { return locationDisclosure; }
    public Bitmap getMapSnapshotBitmap() { return mapSnapshotBitmap; }
    public void setMapSnapshotBitmap(Bitmap mapSnapshotBitmap) { this.mapSnapshotBitmap = mapSnapshotBitmap; }
    public String getMapSnapshotStatus() { return mapSnapshotStatus; }
    public void setMapSnapshotStatus(String mapSnapshotStatus) { this.mapSnapshotStatus = mapSnapshotStatus; }
}
