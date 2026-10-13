package com.example.spyaware.report;

import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.model.TargetLocationPoint;
import com.example.spyaware.model.UserLocationPoint;
import com.example.spyaware.security.RiskEngine;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class DeviceReportDataTest {

    @Test
    public void testReportGenerationWithCompleteData() {
        long t0 = System.currentTimeMillis() - 60000;
        DeviceModel device = new DeviceModel("AirTag Tracker", "DC:2C:26:11:22:33", -65, "10:00:00", "10:01:00");
        device.setFirstSeenTimestamp(t0);
        device.setLastSeenTimestamp(t0 + 60000);
        device.setAdvertisementData("ID=0x004C:02154F", "0000FD6F-0000-1000-8000-00805F9B34FB", 0);
        device.setBleFingerprint("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");

        // Add RSSI history
        device.addRssiObservation(-70, t0 + 10000);
        device.addRssiObservation(-68, t0 + 20000);
        device.addRssiObservation(-62, t0 + 30000);
        device.addRssiObservation(-58, t0 + 40000);

        // Add GPS target locations
        device.recordTargetLocation(37.7749, -122.4194, t0 + 20000);
        device.recordTargetLocation(37.7751, -122.4196, t0 + 40000);

        List<UserLocationPoint> userLocations = new ArrayList<>();
        userLocations.add(new UserLocationPoint(t0 + 10000, 37.7748, -122.4193));
        userLocations.add(new UserLocationPoint(t0 + 30000, 37.7750, -122.4195));

        DeviceReportData report = DeviceReportData.fromDeviceModel(device, userLocations);

        assertNotNull(report.getReportId());
        assertTrue(report.getReportId().startsWith("REP-"));
        assertEquals("1.0", report.getReportVersion());
        assertEquals("AirTag Tracker", report.getDeviceName());
        assertEquals("DC:2C:26:11:22:33", report.getMacAddress());
        assertTrue(report.getResolvedManufacturer().contains("Apple"));
        assertEquals(0, report.getTxPower());
        assertEquals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", report.getBleFingerprint());

        // Observation window
        assertTrue(report.getElapsedWindowMs() >= 60000);
        assertTrue(report.getPacketCount() >= 5);

        // Signal analysis
        assertTrue(report.getRssiHistory().size() >= 4);
        assertTrue(report.getCurrentEstimatedDistance() > 0);
        assertNotNull(report.getRssiTrend());

        // Score breakdown & evidence
        assertTrue(report.getRiskScore() >= 0 && report.getRiskScore() <= 100);
        assertFalse(report.scoreComponents().isEmpty());
        assertFalse(report.getFlaggedEvidence().isEmpty());
        assertFalse(report.getFactsVsInferences().isEmpty());
        assertFalse(report.getRecommendedNextSteps().isEmpty());

        // Locations
        assertEquals(2, report.getTargetLocationPoints().size());
        assertEquals(2, report.getUserLocationPoints().size());
        assertNotNull(report.getLocationDisclosure());
    }

    @Test
    public void testMissingDeviceNameAndManufacturer() {
        DeviceModel device = new DeviceModel("", "AA:BB:CC:DD:EE:FF", -80, "12:00:00", "12:00:05");
        device.setAdvertisementData("None", "None", Integer.MIN_VALUE);

        DeviceReportData report = DeviceReportData.fromDeviceModel(device, Collections.emptyList());

        assertEquals("Unknown BLE Device", report.getDeviceName());
        assertEquals("AA:BB:CC:DD:EE:FF", report.getMacAddress());
        assertEquals("None Reported", report.getResolvedManufacturer());
        assertEquals("None", report.getServiceUuids());
        assertEquals(Integer.MIN_VALUE, report.getTxPower());
        assertNotNull(report.getIdentityConfidence());
    }

    @Test
    public void testEmptyOrSingleRssiHistory() {
        DeviceModel device = new DeviceModel("Solo Device", "11:22:33:44:55:66", -75, "12:00:00", "12:00:00");

        DeviceReportData report = DeviceReportData.fromDeviceModel(device, null);

        assertNotNull(report);
        assertEquals(1, report.getPacketCount());
        assertEquals(-75, report.getLatestRssi());
        assertEquals(-75.0, report.getAverageRssi(), 0.1);
        assertEquals(-75, report.getMinRssi());
        assertEquals(-75, report.getMaxRssi());
        assertNotNull(report.getRssiTrend());
        assertTrue(report.getCurrentEstimatedDistance() > 0);
    }

    @Test
    public void testMultipleObservationSessions() {
        long baseTime = 1000000L;
        DeviceModel device = new DeviceModel("Session Test Device", "AA:AA:AA:AA:AA:AA", -70, "09:00:00", "09:00:00");
        device.setFirstSeenTimestamp(baseTime);

        // Session 1: 0 to 5 seconds
        device.recordPresence(baseTime);
        device.recordPresence(baseTime + 5000);

        // Gap: 15 seconds without presence (exceeds 10s PRESENCE_TIMEOUT)
        device.checkPresenceTimeout(baseTime + 20000);
        assertFalse(device.isCurrentlyPresent());

        // Session 2: starts at 25 seconds
        device.recordPresence(baseTime + 25000);
        device.recordPresence(baseTime + 30000);
        device.setLastSeenTimestamp(baseTime + 30000);

        DeviceReportData report = DeviceReportData.fromDeviceModel(device, null);

        assertEquals(2, report.getSessionCount());
        List<DeviceModel.ObservationSession> sessions = report.getSessions();
        assertTrue(sessions.size() >= 2);

        // Verify active presence duration excludes unobserved gap
        long totalElapsed = report.getElapsedWindowMs();
        long activeDuration = report.getActivePresenceDurationMs();
        assertTrue("Active duration should be less than total elapsed window", activeDuration < totalElapsed);
    }

    @Test
    public void testMissingGpsHistory() {
        DeviceModel device = new DeviceModel("No GPS Device", "55:66:77:88:99:00", -70, "11:00:00", "11:05:00");

        DeviceReportData report = DeviceReportData.fromDeviceModel(device, null);

        assertTrue(report.getTargetLocationPoints().isEmpty());
        assertTrue(report.getUserLocationPoints().isEmpty());
        assertNull(report.getMapSnapshotBitmap());
        assertTrue(report.getMapSnapshotStatus().contains("0"));
        assertNotNull(report.getLocationDisclosure());
    }

    @Test
    public void testMapSnapshotFailureHandling() {
        DeviceModel device = new DeviceModel("Snapshot Test", "99:88:77:66:55:44", -65, "11:00:00", "11:01:00");
        DeviceReportData report = DeviceReportData.fromDeviceModel(device, null);

        // Map snapshot is null (failed or unavailable)
        report.setMapSnapshotBitmap(null);
        report.setMapSnapshotStatus("Snapshot capture timed out or map not ready");

        assertNull(report.getMapSnapshotBitmap());
        assertEquals("Snapshot capture timed out or map not ready", report.getMapSnapshotStatus());
    }

    @Test
    public void testDataIsolationBetweenTwoDevices() {
        DeviceModel deviceA = new DeviceModel("Device Alpha", "AA:11:11:11:11:11", -55, "10:00:00", "10:10:00");
        deviceA.addRssiObservation(-50, 1000L);
        deviceA.recordTargetLocation(10.0, 20.0, 1000L);

        DeviceModel deviceB = new DeviceModel("Device Beta", "BB:22:22:22:22:22", -85, "11:00:00", "11:20:00");
        deviceB.addRssiObservation(-90, 2000L);
        deviceB.addRssiObservation(-92, 3000L);
        deviceB.recordTargetLocation(30.0, 40.0, 2000L);

        DeviceReportData reportA = DeviceReportData.fromDeviceModel(deviceA, null);
        DeviceReportData reportB = DeviceReportData.fromDeviceModel(deviceB, null);

        // Verify Device A data
        assertEquals("AA:11:11:11:11:11", reportA.getMacAddress());
        assertEquals("Device Alpha", reportA.getDeviceName());
        assertEquals(1, reportA.getTargetLocationPoints().size());
        assertEquals(10.0, reportA.getTargetLocationPoints().get(0).getLatitude(), 0.001);

        // Verify Device B data
        assertEquals("BB:22:22:22:22:22", reportB.getMacAddress());
        assertEquals("Device Beta", reportB.getDeviceName());
        assertEquals(1, reportB.getTargetLocationPoints().size());
        assertEquals(30.0, reportB.getTargetLocationPoints().get(0).getLatitude(), 0.001);

        // Verify independence
        assertNotEquals(reportA.getReportId(), reportB.getReportId());
        assertNotEquals(reportA.getMacAddress(), reportB.getMacAddress());
    }

    @Test
    public void testFactsVsInferencesDistinction() {
        DeviceModel device = new DeviceModel("Beacon", "12:34:56:78:9A:BC", -60, "08:00:00", "08:05:00");
        DeviceReportData report = DeviceReportData.fromDeviceModel(device, null);

        List<DeviceReportData.FactInferencePair> pairs = report.getFactsVsInferences();
        assertFalse(pairs.isEmpty());

        for (DeviceReportData.FactInferencePair pair : pairs) {
            assertNotNull(pair.getMeasuredFact());
            assertNotNull(pair.getAlgorithmicInference());
            assertFalse(pair.getMeasuredFact().isEmpty());
            assertFalse(pair.getAlgorithmicInference().isEmpty());
        }
    }

    @Test
    public void testRiskEngineBreakdownConsistency() {
        DeviceModel device = new DeviceModel("Risk Target", "FF:EE:DD:CC:BB:AA", -50, "09:00:00", "09:02:00");
        device.setDeviceClassification(DeviceModel.CLASS_UNKNOWN); // +10

        device.updateRiskAssessment();
        int expectedScore = RiskEngine.calculateRiskScore(device);
        String expectedLevel = RiskEngine.getRiskLevel(expectedScore);

        DeviceReportData report = DeviceReportData.fromDeviceModel(device, null);

        assertEquals(expectedScore, report.getRiskScore());
        assertEquals(expectedLevel, report.getRiskLevel());
    }
}
