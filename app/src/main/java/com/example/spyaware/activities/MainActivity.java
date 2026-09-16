package com.example.spyaware.activities;

import android.bluetooth.BluetoothDevice;
import android.content.Intent;
import com.example.spyaware.model.KnownDevice;
import com.example.spyaware.model.KnownDeviceRegistry;
import com.example.spyaware.security.AlertEngine;
import com.example.spyaware.bluetooth.BleDeviceRegistry;
import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.adapter.DeviceAdapter;
import android.os.Handler;
import android.os.Looper;
import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelUuid;
import android.util.SparseArray;
import android.widget.Button;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.spyaware.R;
import com.example.spyaware.adapter.DeviceAdapter;
import com.example.spyaware.model.DeviceModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private final Handler presenceHandler =
            new Handler(Looper.getMainLooper());

    private boolean presenceMonitoring = false;
    private Button btnStartScan;
    private Button btnStopScan;
    private Button btnRegisterKnown;
    private RecyclerView recyclerDevices;

    private DeviceAdapter adapter;
    public static List<DeviceModel> deviceList;

    private AlertEngine alertEngine;
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothLeScanner bluetoothLeScanner;
    private KnownDeviceRegistry knownDeviceRegistry;
    private DeviceModel selectedDevice;
    private static final int PERMISSION_REQUEST_CODE = 100;


    // =========================================================
    // Convert byte array to HEX
    // =========================================================

    private String bytesToHex(byte[] bytes) {

        if (bytes == null || bytes.length == 0) {
            return "";
        }

        StringBuilder result = new StringBuilder();

        for (byte b : bytes) {

            result.append(
                    String.format(
                            Locale.US,
                            "%02X",
                            b & 0xFF
                    )
            );
        }

        return result.toString();
    }


    // =========================================================
    // Generate BLE Fingerprint
    // =========================================================

    private String generateBleFingerprint(
            ScanRecord scanRecord
    ) {

        if (scanRecord == null) {
            return "Unknown";
        }

        StringBuilder signature =
                new StringBuilder();


        // -----------------------------------------------------
        // Manufacturer IDs
        // -----------------------------------------------------

        SparseArray<byte[]> manufacturer =
                scanRecord.getManufacturerSpecificData();

        if (manufacturer != null) {

            for (int i = 0;
                 i < manufacturer.size();
                 i++) {

                signature
                        .append("M:")
                        .append(manufacturer.keyAt(i))
                        .append(";");

            }
        }


        // -----------------------------------------------------
        // Service UUIDs
        // -----------------------------------------------------

        List<ParcelUuid> uuids =
                scanRecord.getServiceUuids();

        if (uuids != null) {

            for (ParcelUuid uuid : uuids) {

                signature
                        .append("U:")
                        .append(uuid.toString())
                        .append(";");

            }
        }


        // -----------------------------------------------------
        // Service Data
        // -----------------------------------------------------

        Map<ParcelUuid, byte[]> serviceData =
                scanRecord.getServiceData();

        if (serviceData != null) {

            for (ParcelUuid uuid :
                    serviceData.keySet()) {

                byte[] data =
                        serviceData.get(uuid);

                signature
                        .append("SD:")
                        .append(uuid.toString())
                        .append(":LEN=")
                        .append(
                                data == null
                                        ? 0
                                        : data.length
                        )
                        .append(";");

            }
        }


        // -----------------------------------------------------
        // Raw Advertisement Length
        // -----------------------------------------------------

        byte[] raw =
                scanRecord.getBytes();

        if (raw != null) {

            signature
                    .append("RAWLEN:")
                    .append(raw.length)
                    .append(";");

        }


        // -----------------------------------------------------
        // TX Power Presence
        // -----------------------------------------------------

        int txPower =
                scanRecord.getTxPowerLevel();

        signature
                .append("TX:")
                .append(
                        txPower != Integer.MIN_VALUE
                                ? "PRESENT"
                                : "ABSENT"
                );


        // -----------------------------------------------------
        // SHA-256
        // -----------------------------------------------------

        try {

            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash =
                    digest.digest(
                            signature
                                    .toString()
                                    .getBytes(
                                            StandardCharsets.UTF_8
                                    )
                    );

            StringBuilder hex =
                    new StringBuilder();

            for (byte b : hash) {

                hex.append(
                        String.format(
                                Locale.US,
                                "%02X",
                                b & 0xFF
                        )
                );
            }

            return hex.toString();

        } catch (NoSuchAlgorithmException e) {

            return signature.toString();
        }
    }
    // =========================================================
// REGISTER REAL DEVICE AS KNOWN
// =========================================================

    private void registerDeviceAsKnown(DeviceModel device) {

        if (device == null) {
            return;
        }

        String fingerprint =
                device.getBleFingerprint();

        if (fingerprint == null ||
                fingerprint.isEmpty() ||
                fingerprint.equals("Unknown")) {

            Toast.makeText(
                    this,
                    "Cannot register device: BLE fingerprint unavailable",
                    Toast.LENGTH_LONG
            ).show();

            return;
        }

        // Use the current averaged RSSI as the
        // calibration reference.
        double referenceRssi =
                device.getAverageRssi();

        KnownDevice knownDevice =
                new KnownDevice(
                        device.getDeviceName(),
                        fingerprint,
                        referenceRssi
                );

        knownDeviceRegistry.addKnownDevice(
                knownDevice
        );

        // Immediately classify this device
        device.classifyDevice(
                knownDeviceRegistry
        );

        Toast.makeText(
                this,
                device.getDeviceName()
                        + " registered as KNOWN",
                Toast.LENGTH_SHORT
        ).show();

        adapter.notifyDataSetChanged();
    }

    // =========================================================
    // ON CREATE
    // =========================================================

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_main);
        alertEngine = new AlertEngine();
        knownDeviceRegistry =
                KnownDeviceRegistry.getInstance();

        // -----------------------------------------------------
        // UI
        // -----------------------------------------------------

        btnStartScan =
                findViewById(R.id.btnStartScan);

        btnStopScan =
                findViewById(R.id.btnStopScan);
        Button btnKnownDevices =
                findViewById(R.id.btnKnownDevices);
        btnRegisterKnown =
                findViewById(R.id.btnRegisterKnown);

        recyclerDevices =
                findViewById(R.id.recyclerDevices);


        // -----------------------------------------------------
        // Device List
        // -----------------------------------------------------

        deviceList =
                new ArrayList<>();

        adapter =
                new DeviceAdapter(
                        deviceList,
                        device -> {

                            // Remember selected device
                            selectedDevice = device;

                            Toast.makeText(
                                    MainActivity.this,
                                    "Selected: " +
                                            device.getDeviceName(),
                                    Toast.LENGTH_SHORT
                            ).show();

                            Intent intent =
                                    new Intent(
                                            MainActivity.this,
                                            DeviceDetailsActivity.class
                                    );

                            intent.putExtra(
                                    "deviceIdentifier",
                                    device.getMacAddress()
                            );

                            startActivity(intent);
                        }
                );

        recyclerDevices.setLayoutManager(
                new LinearLayoutManager(this)
        );

        recyclerDevices.setAdapter(adapter);


        // -----------------------------------------------------
        // Permissions
        // -----------------------------------------------------

        requestPermissions();


        // -----------------------------------------------------
        // Bluetooth
        // -----------------------------------------------------

        BluetoothManager bluetoothManager =
                (BluetoothManager)
                        getSystemService(
                                BLUETOOTH_SERVICE
                        );

        bluetoothAdapter =
                bluetoothManager.getAdapter();


        if (bluetoothAdapter == null) {

            Toast.makeText(
                    this,
                    "Bluetooth is not supported on this device",
                    Toast.LENGTH_LONG
            ).show();

            finish();

            return;
        }


        bluetoothLeScanner =
                bluetoothAdapter.getBluetoothLeScanner();


        // =====================================================
        // START SCAN
        // =====================================================

        btnStartScan.setOnClickListener(v -> {

            if (!bluetoothAdapter.isEnabled()) {

                Toast.makeText(
                        this,
                        "Please enable Bluetooth",
                        Toast.LENGTH_SHORT
                ).show();

                return;
            }


            // -------------------------------------------------
            // Check Location
            // -------------------------------------------------

            android.location.LocationManager
                    locationManager =
                    (android.location.LocationManager)
                            getSystemService(
                                    LOCATION_SERVICE
                            );


            if (locationManager == null ||
                    !locationManager.isLocationEnabled()) {

                Toast.makeText(
                        this,
                        "Please turn on Location (GPS) for BLE scan results",
                        Toast.LENGTH_LONG
                ).show();

                startActivity(
                        new android.content.Intent(
                                android.provider.Settings
                                        .ACTION_LOCATION_SOURCE_SETTINGS
                        )
                );

                return;
            }


            // -------------------------------------------------
            // Permission Check
            // -------------------------------------------------

            if (Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.S) {

                if (ActivityCompat.checkSelfPermission(
                        this,
                        Manifest.permission.BLUETOOTH_SCAN
                ) != PackageManager.PERMISSION_GRANTED ||

                        ActivityCompat.checkSelfPermission(
                                this,
                                Manifest.permission.ACCESS_FINE_LOCATION
                        ) != PackageManager.PERMISSION_GRANTED) {

                    requestPermissions();

                    return;
                }
            }


            // -------------------------------------------------
            // Start BLE Scan
            // -------------------------------------------------

            if (bluetoothLeScanner != null) {

                bluetoothLeScanner.startScan(scanCallback);

                startPresenceMonitoring();

                Toast.makeText(this,
                        "Scanning Started",
                        Toast.LENGTH_SHORT).show();

            } else {

                Toast.makeText(
                        this,
                        "BLE Scanner not available",
                        Toast.LENGTH_SHORT
                ).show();
            }

        });


        // =====================================================
        // STOP SCAN
        // =====================================================

        btnStopScan.setOnClickListener(v -> {

            if (Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.S) {

                if (ActivityCompat.checkSelfPermission(
                        this,
                        Manifest.permission.BLUETOOTH_SCAN
                ) != PackageManager.PERMISSION_GRANTED) {

                    return;
                }
            }


            if (bluetoothLeScanner != null) {

                bluetoothLeScanner.stopScan(scanCallback);

                stopPresenceMonitoring();

                Toast.makeText(this,
                        "Scanning Stopped",
                        Toast.LENGTH_SHORT).show();
            }

        });
        btnKnownDevices.setOnClickListener(v -> {

            Intent intent =
                    new Intent(
                            MainActivity.this,
                            KnownDevicesActivity.class
                    );

            startActivity(intent);
        });
        btnRegisterKnown.setOnClickListener(v -> {

            if (selectedDevice == null) {

                Toast.makeText(
                        this,
                        "Select a device first",
                        Toast.LENGTH_SHORT
                ).show();

                return;
            }

            registerDeviceAsKnown(
                    selectedDevice
            );
        });
    }


    // =========================================================
    // BLE SCAN CALLBACK
    // =========================================================

    private final ScanCallback scanCallback =
            new ScanCallback() {

                @Override
                public void onScanResult(
                        int callbackType,
                        ScanResult result
                ) {

                    // -------------------------------------------------
                    // Basic device information
                    // -------------------------------------------------

                    BluetoothDevice device =
                            result.getDevice();

                    String address =
                            device.getAddress();

                    String name =
                            device.getName();


                    if (name == null ||
                            name.isEmpty()) {

                        name =
                                "Unknown BLE Device";
                    }


                    int rssi =
                            result.getRssi();


                    long timestamp =
                            System.currentTimeMillis();
                    long now = System.currentTimeMillis();

                    String formattedTime =
                            new SimpleDateFormat(
                                    "HH:mm:ss",
                                    Locale.getDefault()
                            ).format(new Date(now));


                    // -------------------------------------------------
                    // ScanRecord
                    // -------------------------------------------------

                    ScanRecord scanRecord =
                            result.getScanRecord();


                    String manufacturerData =
                            "None";

                    String serviceUuids =
                            "None";

                    int txPower =
                            Integer.MIN_VALUE;


                    // -------------------------------------------------
                    // Extract Advertisement Data
                    // -------------------------------------------------

                    if (scanRecord != null) {


                        // ---------------------------------------------
                        // Manufacturer Data
                        // ---------------------------------------------

                        SparseArray<byte[]> manufacturer =
                                scanRecord
                                        .getManufacturerSpecificData();


                        if (manufacturer != null &&
                                manufacturer.size() > 0) {

                            StringBuilder manufacturerBuilder =
                                    new StringBuilder();


                            for (int i = 0;
                                 i < manufacturer.size();
                                 i++) {

                                int manufacturerId =
                                        manufacturer.keyAt(i);


                                byte[] data =
                                        manufacturer.valueAt(i);


                                manufacturerBuilder
                                        .append("ID=0x")
                                        .append(
                                                String.format(
                                                        Locale.US,
                                                        "%04X",
                                                        manufacturerId
                                                )
                                        )
                                        .append(":")
                                        .append(
                                                bytesToHex(data)
                                        );


                                if (i <
                                        manufacturer.size() - 1) {

                                    manufacturerBuilder
                                            .append(" | ");
                                }
                            }


                            manufacturerData =
                                    manufacturerBuilder.toString();
                        }


                        // ---------------------------------------------
                        // Service UUIDs
                        // ---------------------------------------------

                        List<ParcelUuid> uuids =
                                scanRecord.getServiceUuids();


                        if (uuids != null &&
                                !uuids.isEmpty()) {

                            StringBuilder uuidBuilder =
                                    new StringBuilder();


                            for (int i = 0;
                                 i < uuids.size();
                                 i++) {

                                uuidBuilder
                                        .append(
                                                uuids
                                                        .get(i)
                                                        .toString()
                                        );


                                if (i <
                                        uuids.size() - 1) {

                                    uuidBuilder
                                            .append(", ");
                                }
                            }


                            serviceUuids =
                                    uuidBuilder.toString();
                        }


                        // ---------------------------------------------
                        // TX Power
                        // ---------------------------------------------

                        txPower =
                                scanRecord.getTxPowerLevel();
                    }


                    // =================================================
                    // GENERATE FINGERPRINT
                    // =================================================

                    String bleFingerprint =
                            generateBleFingerprint(
                                    scanRecord
                            );


                    // -------------------------------------------------
                    // Time
                    // -------------------------------------------------

                    String currentTime =
                            new SimpleDateFormat(
                                    "HH:mm:ss",
                                    Locale.getDefault()
                            ).format(
                                    new Date(timestamp)
                            );


                    // =================================================
                    // FIND EXISTING DEVICE
                    // =================================================

                    int existingIndex = -1;


                    for (int i = 0;
                         i < deviceList.size();
                         i++) {

                        if (deviceList
                                .get(i)
                                .getMacAddress()
                                .equals(address)) {

                            existingIndex = i;

                            break;
                        }
                    }


                    // =================================================
                    // NEW DEVICE
                    // =================================================

                    if (existingIndex == -1) {

                        DeviceModel newDevice =
                                new DeviceModel(
                                        name,
                                        address,
                                        rssi,
                                        currentTime,
                                        currentTime
                                );
                        newDevice.recordPresence(now);


                        // Advertisement information
                        newDevice.setAdvertisementData(
                                manufacturerData,
                                serviceUuids,
                                txPower
                        );


                        // BLE fingerprint
                        newDevice.setBleFingerprint(
                                bleFingerprint
                        );
                        newDevice.classifyDevice(
                                knownDeviceRegistry
                        );

                        newDevice.updateRiskAssessment();

                        deviceList.add(
                                newDevice
                        );

                        alertEngine.evaluateDevice(
                                MainActivity.this,
                                newDevice
                        );

                    }


                    // =================================================
                    // EXISTING DEVICE
                    // =================================================

                    else {

                        DeviceModel existingDevice =
                                deviceList.get(
                                        existingIndex
                                );


                        // Update RSSI + packet count
                        existingDevice.updateDevice(
                                name,
                                rssi,
                                currentTime
                        );
                        existingDevice.recordPresence(now);


                        // Update advertisement data
                        existingDevice.setAdvertisementData(
                                manufacturerData,
                                serviceUuids,
                                txPower
                        );


                        // Update fingerprint
                        existingDevice.setBleFingerprint(
                                bleFingerprint
                        );
                        existingDevice.classifyDevice(
                                knownDeviceRegistry
                        );

                        existingDevice.updateRiskAssessment();

                        alertEngine.evaluateDevice(
                                MainActivity.this,
                                existingDevice
                        );
                    }


                    // =================================================
                    // UPDATE UI
                    // =================================================

                    runOnUiThread(() -> {

                        adapter.notifyDataSetChanged();

                    });
                }
            };


    // =========================================================
    // PERMISSIONS
    // =========================================================

    private void requestPermissions() {

        if (Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.S) {

            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.BLUETOOTH_SCAN
            ) != PackageManager.PERMISSION_GRANTED ||

                    ContextCompat.checkSelfPermission(
                            this,
                            Manifest.permission.BLUETOOTH_CONNECT
                    ) != PackageManager.PERMISSION_GRANTED ||

                    ContextCompat.checkSelfPermission(
                            this,
                            Manifest.permission.ACCESS_FINE_LOCATION
                    ) != PackageManager.PERMISSION_GRANTED) {


                ActivityCompat.requestPermissions(
                        this,

                        new String[]{
                                Manifest.permission.BLUETOOTH_SCAN,
                                Manifest.permission.BLUETOOTH_CONNECT,
                                Manifest.permission.ACCESS_FINE_LOCATION
                        },

                        PERMISSION_REQUEST_CODE
                );
            }

        } else {

            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.ACCESS_FINE_LOCATION
            ) != PackageManager.PERMISSION_GRANTED) {

                ActivityCompat.requestPermissions(
                        this,

                        new String[]{
                                Manifest.permission.ACCESS_FINE_LOCATION
                        },

                        PERMISSION_REQUEST_CODE
                );
            }
        }
    }


    // =========================================================
    // PERMISSION RESULT
    // =========================================================

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            @NonNull String[] permissions,
            @NonNull int[] grantResults
    ) {

        super.onRequestPermissionsResult(
                requestCode,
                permissions,
                grantResults
        );


        if (requestCode ==
                PERMISSION_REQUEST_CODE) {

            boolean granted = true;


            for (int result :
                    grantResults) {

                if (result !=
                        PackageManager.PERMISSION_GRANTED) {

                    granted = false;

                    break;
                }
            }


            if (granted) {

                Toast.makeText(
                        this,
                        "Permissions Granted",
                        Toast.LENGTH_SHORT
                ).show();

            } else {

                Toast.makeText(
                        this,
                        "Permissions Denied",
                        Toast.LENGTH_SHORT
                ).show();
            }
        }
    }
    private void checkDevicePresence() {

        long currentTime = System.currentTimeMillis();

        for (DeviceModel device : deviceList) {

            device.checkPresenceTimeout(currentTime);

            device.updateRiskAssessment();

            alertEngine.evaluateDevice(
                    MainActivity.this,
                    device
            );
        }

        adapter.notifyDataSetChanged();

        if (presenceMonitoring) {

            presenceHandler.postDelayed(
                    this::checkDevicePresence,
                    1000
            );
        }
    }
    private void startPresenceMonitoring() {

        if (presenceMonitoring) {
            return;
        }

        presenceMonitoring = true;

        presenceHandler.post(
                this::checkDevicePresence
        );
    }
    private void stopPresenceMonitoring() {

        presenceMonitoring = false;

        presenceHandler.removeCallbacksAndMessages(null);
    }

}