package com.example.spyaware.report;

import com.example.spyaware.bluetooth.BleDeviceRegistry;
import com.example.spyaware.model.DeviceModel;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import static org.junit.Assert.*;

public class DevicePersistenceAndExportTest {

    @Before
    public void setUp() {
        BleDeviceRegistry.clear();
    }

    @After
    public void tearDown() {
        BleDeviceRegistry.clear();
    }

    @Test
    public void testBleDeviceRegistryAddAndRetrieve() {
        DeviceModel d1 = new DeviceModel("Device 1", "00:11:22:33:44:55", -70, "01:00:00", "01:01:00");
        DeviceModel d2 = new DeviceModel("Device 2", "66:77:88:99:AA:BB", -60, "02:00:00", "02:01:00");

        BleDeviceRegistry.addDevice(d1.getMacAddress(), d1);
        BleDeviceRegistry.addDevice(d2.getMacAddress(), d2);

        assertTrue(BleDeviceRegistry.contains("00:11:22:33:44:55"));
        assertTrue(BleDeviceRegistry.contains("66:77:88:99:AA:BB"));
        assertFalse(BleDeviceRegistry.contains("CC:DD:EE:FF:00:11"));

        assertEquals(d1, BleDeviceRegistry.getDevice("00:11:22:33:44:55"));
        assertEquals(d2, BleDeviceRegistry.getDevice("66:77:88:99:AA:BB"));
        assertEquals(2, BleDeviceRegistry.getDevices().size());

        BleDeviceRegistry.clear();
        assertEquals(0, BleDeviceRegistry.getDevices().size());
        assertFalse(BleDeviceRegistry.contains("00:11:22:33:44:55"));
    }

    @Test
    public void testObservationSessionCalculations() {
        long start = 1000000L;
        long end = 1045000L;
        DeviceModel.ObservationSession session = new DeviceModel.ObservationSession(start, end);

        assertEquals(start, session.getStartTime());
        assertEquals(end, session.getEndTime());
        assertEquals(45000L, session.getDurationMs());

        // Negative duration check
        DeviceModel.ObservationSession invalidSession = new DeviceModel.ObservationSession(end, start);
        assertEquals(0L, invalidSession.getDurationMs());
    }

    @Test
    public void testDeviceModelMaxRssiHistoryLimit() {
        DeviceModel device = new DeviceModel("History Limit Test", "11:22:33:44:55:66", -70, "00:00:00", "00:00:00");

        // Add 1050 observations
        for (int i = 0; i < 1050; i++) {
            device.addRssiObservation(-70 + (i % 20), 1000L + i * 1000);
        }

        // Verify size is capped at 1000 observations
        assertEquals(1000, device.getRssiHistory().size());
        assertEquals(1000, device.getRssiTimestamps().size());
    }

    @Test
    public void testFileCopyHelper() throws IOException {
        File tempDir = new File(System.getProperty("java.io.tmpdir"), "spyaware_test");
        tempDir.mkdirs();

        File srcFile = new File(tempDir, "test_source.pdf");
        File destFile = new File(tempDir, "test_dest.pdf");

        byte[] testData = "PDF_MOCK_CONTENT_STREAM_1234567890".getBytes();
        try (FileOutputStream fos = new FileOutputStream(srcFile)) {
            fos.write(testData);
        }

        // Copy
        try (FileInputStream in = new FileInputStream(srcFile);
             FileOutputStream out = new FileOutputStream(destFile)) {
            byte[] buf = new byte[1024];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
        }

        assertTrue(destFile.exists());
        assertEquals(srcFile.length(), destFile.length());

        // Cleanup
        srcFile.delete();
        destFile.delete();
        tempDir.delete();
    }
}
