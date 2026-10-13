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
import android.view.View;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.spyaware.R;
import com.example.spyaware.adapter.DeviceAdapter;
import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.security.RiskEngine;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import android.location.Location;

import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationCallback;
import com.google.android.gms.location.LocationRequest;
import com.google.android.gms.location.LocationResult;
import com.google.android.gms.location.LocationServices;
import com.example.spyaware.model.UserLocationPoint;
import com.google.android.gms.location.Priority;

public class MainActivity extends AppCompatActivity {

    private final Handler presenceHandler =
            new Handler(Looper.getMainLooper());

    private boolean presenceMonitoring = false;
    private Button btnStartScan;
    private Button btnStopScan;
    private Button btnRegisterKnown;
    private RecyclerView recyclerDevices;
    private RecyclerView recyclerTargets;

    private com.google.android.material.tabs.TabLayout deviceTabs;

    private android.widget.FrameLayout nearbyContainer;
    private android.widget.FrameLayout targetContainer;

    private com.google.android.material.tabs.TabLayout targetTabs;

    private android.widget.FrameLayout targetListContainer;
    private android.widget.FrameLayout targetMapContainer;

    private android.widget.TextView tvNoTargets;

    private DeviceAdapter targetAdapter;

    private List<DeviceModel> potentialTargetList;
    private DeviceAdapter adapter;
    public static List<DeviceModel> deviceList;
    // ============================================================
// USER LOCATION TRACKING
// ============================================================

    private FusedLocationProviderClient fusedLocationClient;

    private LocationCallback locationCallback;

    private Location latestUserLocation;
    private static final long TARGET_LOCATION_RECORD_INTERVAL_MS = 2000;

    private final java.util.Map<String, Long>
            targetLocationRecordTimes =
            new java.util.HashMap<>();

    private boolean locationTrackingStarted = false;
    public static final List<UserLocationPoint>
            userLocationHistory =
            new ArrayList<>();

    private static final int MAX_USER_LOCATION_HISTORY = 2000;

    private long lastUserLocationRecordTime = 0;

    private static final long
            USER_LOCATION_RECORD_INTERVAL_MS = 2000;

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
        fusedLocationClient =
                LocationServices.getFusedLocationProviderClient(this);
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
        recyclerTargets =
                findViewById(R.id.recyclerTargets);

        deviceTabs =
                findViewById(R.id.deviceTabs);

        nearbyContainer =
                findViewById(R.id.nearbyContainer);

        targetContainer =
                findViewById(R.id.targetContainer);

        tvNoTargets =
                findViewById(R.id.tvNoTargets);

        targetTabs =
                findViewById(R.id.targetTabs);

        targetListContainer =
                findViewById(R.id.targetListContainer);

        targetMapContainer =
                findViewById(R.id.targetMapContainer);

        deviceTabs.addOnTabSelectedListener(
                new com.google.android.material.tabs.TabLayout.OnTabSelectedListener() {

                    @Override
                    public void onTabSelected(
                            com.google.android.material.tabs.TabLayout.Tab tab) {

                        if (tab.getPosition() == 0) {

                            // ============================================
                            // NEARBY BLE DEVICES
                            // ============================================

                            nearbyContainer.setVisibility(
                                    View.VISIBLE
                            );

                            targetContainer.setVisibility(
                                    View.GONE
                            );

                        } else {

                            // ============================================
                            // POTENTIAL TARGETS
                            // ============================================

                            nearbyContainer.setVisibility(
                                    View.GONE
                            );

                            targetContainer.setVisibility(
                                    View.VISIBLE
                            );

                            updatePotentialTargets();
                        }
                    }

                    @Override
                    public void onTabUnselected(
                            com.google.android.material.tabs.TabLayout.Tab tab) {
                        // Nothing needed
                    }

                    @Override
                    public void onTabReselected(
                            com.google.android.material.tabs.TabLayout.Tab tab) {
                        // Nothing needed
                    }
                }
        );
        // =========================================================
// POTENTIAL TARGET INNER TABS
// =========================================================

        targetTabs.addOnTabSelectedListener(
                new com.google.android.material.tabs.TabLayout
                        .OnTabSelectedListener() {

                    @Override
                    public void onTabSelected(
                            com.google.android.material.tabs.TabLayout.Tab tab) {

                        if (tab.getPosition() == 0) {

                            // -----------------------------------------
                            // TARGET LIST
                            // -----------------------------------------

                            targetListContainer.setVisibility(
                                    View.VISIBLE
                            );

                            targetMapContainer.setVisibility(
                                    View.GONE
                            );

                        } else {

                            // -----------------------------------------
                            // TARGET MAP
                            // -----------------------------------------

                            targetListContainer.setVisibility(
                                    View.GONE
                            );

                            targetMapContainer.setVisibility(
                                    View.VISIBLE
                            );

                            openPotentialTargetsMap();
                        }
                    }

                    @Override
                    public void onTabUnselected(
                            com.google.android.material.tabs.TabLayout.Tab tab) {
                    }

                    @Override
                    public void onTabReselected(
                            com.google.android.material.tabs.TabLayout.Tab tab) {

                        if (tab.getPosition() == 1) {

                            openPotentialTargetsMap();
                        }
                    }
                }
        );
        // -----------------------------------------------------
        // Device List
        // -----------------------------------------------------

        deviceList =
                new ArrayList<>();
        potentialTargetList =
                new ArrayList<>();

        BleDeviceRegistry.loadFromStorage(this);
        if (!BleDeviceRegistry.getDevices().isEmpty()) {
            deviceList.addAll(BleDeviceRegistry.getDevices().values());
        }

        adapter =
                new DeviceAdapter(
                        deviceList,
                        new DeviceAdapter.OnDeviceActionListener() {
                            @Override
                            public void onViewDetails(DeviceModel device) {
                                openDeviceDetails(device);
                            }

                            @Override
                            public void onGenerateReport(DeviceModel device) {
                                openDeviceReport(device);
                            }
                        }
                );
        targetAdapter =
                new DeviceAdapter(
                        potentialTargetList,
                        new DeviceAdapter.OnDeviceActionListener() {
                            @Override
                            public void onViewDetails(DeviceModel device) {
                                openDeviceDetails(device);
                            }

                            @Override
                            public void onGenerateReport(DeviceModel device) {
                                openDeviceReport(device);
                            }
                        }
                );

        recyclerTargets.setLayoutManager(
                new LinearLayoutManager(this)
        );

        recyclerTargets.setAdapter(
                targetAdapter
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

                userLocationHistory.clear();

                lastUserLocationRecordTime = 0;

                targetLocationRecordTimes.clear();

                startUserLocationTracking();

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
                        recordCurrentLocationForDevice(
                                newDevice
                        );

                        deviceList.add(
                                newDevice
                        );
                        BleDeviceRegistry.addDevice(address, newDevice);
                        updatePotentialTargets();

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
                        recordCurrentLocationForDevice(existingDevice);
                        BleDeviceRegistry.addDevice(address, existingDevice);
                        updatePotentialTargets();

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
        updatePotentialTargets();

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
    private void updatePotentialTargets() {

        if (potentialTargetList == null) {
            return;
        }

        potentialTargetList.clear();

        for (DeviceModel device : deviceList) {

            // Make sure the latest risk assessment is used
            device.updateRiskAssessment();

            String riskLevel = device.getRiskLevel();

            // Potential targets = HIGH or CRITICAL risk
            if (RiskEngine.HIGH.equals(riskLevel)
                    || RiskEngine.CRITICAL.equals(riskLevel)) {

                potentialTargetList.add(device);
            }
        }

        if (targetAdapter != null) {
            targetAdapter.notifyDataSetChanged();
        }

        if (tvNoTargets != null) {

            if (potentialTargetList.isEmpty()) {
                tvNoTargets.setVisibility(View.VISIBLE);
                tvNoTargets.setText(
                        "No potential targets detected"
                );
            } else {
                tvNoTargets.setVisibility(View.GONE);
            }
        }
    }
    private void startUserLocationTracking() {

        if (locationTrackingStarted) {
            return;
        }

        if (ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.ACCESS_FINE_LOCATION
        ) != PackageManager.PERMISSION_GRANTED
                &&
                ContextCompat.checkSelfPermission(
                        this,
                        Manifest.permission.ACCESS_COARSE_LOCATION
                ) != PackageManager.PERMISSION_GRANTED) {

            ActivityCompat.requestPermissions(
                    this,
                    new String[]{
                            Manifest.permission.ACCESS_FINE_LOCATION,
                            Manifest.permission.ACCESS_COARSE_LOCATION
                    },
                    PERMISSION_REQUEST_CODE
            );

            return;
        }

        LocationRequest locationRequest =
                new LocationRequest.Builder(
                        Priority.PRIORITY_HIGH_ACCURACY,
                        2000
                )
                        .setMinUpdateIntervalMillis(1000)
                        .build();

        locationCallback = new LocationCallback() {

            @Override
            public void onLocationResult(
                    @NonNull LocationResult locationResult) {

                for (Location location :
                        locationResult.getLocations()) {

                    latestUserLocation = location;

                    recordUserLocation(location);
                }
            }
        };

        fusedLocationClient.requestLocationUpdates(
                locationRequest,
                locationCallback,
                Looper.getMainLooper()
        );

        locationTrackingStarted = true;
    }
    private void recordUserLocation(Location location) {

        if (location == null) {
            return;
        }

        long timestamp =
                System.currentTimeMillis();

        if (timestamp - lastUserLocationRecordTime
                < USER_LOCATION_RECORD_INTERVAL_MS) {
            return;
        }

        lastUserLocationRecordTime =
                timestamp;

        UserLocationPoint point =
                new UserLocationPoint(
                        timestamp,
                        location.getLatitude(),
                        location.getLongitude()
                );

        userLocationHistory.add(point);

        if (userLocationHistory.size()
                > MAX_USER_LOCATION_HISTORY) {

            userLocationHistory.remove(0);
        }
    }
    private void recordCurrentLocationForDevice(
            DeviceModel device
    ) {

        if (device == null) {
            return;
        }

        if (latestUserLocation == null) {
            return;
        }

        String deviceId =
                device.getMacAddress();

        if (deviceId == null ||
                deviceId.isEmpty()) {
            return;
        }

        long timestamp =
                System.currentTimeMillis();

        Long lastRecord =
                targetLocationRecordTimes.get(deviceId);

        if (lastRecord != null
                && timestamp - lastRecord
                < TARGET_LOCATION_RECORD_INTERVAL_MS) {

            return;
        }

        targetLocationRecordTimes.put(
                deviceId,
                timestamp
        );

        double latitude =
                latestUserLocation.getLatitude();

        double longitude =
                latestUserLocation.getLongitude();

        device.recordTargetLocation(
                latitude,
                longitude,
                timestamp
        );
    }
    // =========================================================
// OPEN ALL POTENTIAL TARGETS MAP
// =========================================================

    private void openPotentialTargetsMap() {

        updatePotentialTargets();

        Intent intent =
                new Intent(
                        MainActivity.this,
                        PotentialTargetsMapActivity.class
                );

        startActivity(intent);
    }

    @Override
    protected void onPause() {
        super.onPause();
        BleDeviceRegistry.saveToStorage(this);
    }

    private void openDeviceDetails(DeviceModel device) {
        if (device == null) return;
        selectedDevice = device;
        Toast.makeText(
                MainActivity.this,
                "Selected: " + device.getDeviceName(),
                Toast.LENGTH_SHORT
        ).show();

        Intent intent = new Intent(
                MainActivity.this,
                DeviceDetailsActivity.class
        );
        intent.putExtra(
                "deviceIdentifier",
                device.getMacAddress()
        );
        startActivity(intent);
    }

    private void openDeviceReport(DeviceModel device) {
        if (device == null) return;
        selectedDevice = device;
        Intent intent = new Intent(
                MainActivity.this,
                DeviceReportActivity.class
        );
        intent.putExtra(
                "deviceIdentifier",
                device.getMacAddress()
        );
        startActivity(intent);
    }
}