package com.example.spyaware.activities;

import android.Manifest;
import android.content.pm.PackageManager;
import android.location.Location;
import android.os.Bundle;
import android.widget.Toast;
import android.widget.TextView;
import android.widget.Button;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Handler;
import com.example.spyaware.report.ReportSnapshotHolder;

import androidx.activity.EdgeToEdge;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.example.spyaware.R;
import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.model.TargetLocationPoint;
import com.example.spyaware.model.UserLocationPoint;
import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationCallback;
import com.google.android.gms.location.LocationRequest;
import com.google.android.gms.location.LocationResult;
import com.google.android.gms.location.LocationServices;
import com.google.android.gms.location.Priority;
import com.google.android.gms.maps.CameraUpdateFactory;
import com.google.android.gms.maps.GoogleMap;
import com.google.android.gms.maps.OnMapReadyCallback;
import com.google.android.gms.maps.SupportMapFragment;
import com.google.android.gms.maps.model.Circle;
import com.google.android.gms.maps.model.CircleOptions;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.maps.model.Marker;
import com.google.android.gms.maps.model.MarkerOptions;
import com.google.android.gms.maps.model.Polyline;
import com.google.android.gms.maps.model.PolylineOptions;

import java.util.ArrayList;
import java.util.List;

public class PotentialHarmfulActivity
        extends AppCompatActivity
        implements OnMapReadyCallback {

    private static final int LOCATION_PERMISSION_REQUEST = 1001;

    private GoogleMap googleMap;

    private FusedLocationProviderClient fusedLocationClient;

    private LocationCallback locationCallback;

    private Marker currentLocationMarker;

    private String deviceIdentifier;

    private DeviceModel trackedDevice;

    private boolean firstLocationUpdate = true;

    private Polyline userPathPolyline;

    private Circle latestLiveRangeCircle;

    private final List<Circle>
            historicalRangeCircles =
            new ArrayList<>();

    private final List<Polyline>
            dottedRangeLines =
            new ArrayList<>();
    private TextView tvRisk;
    private TextView tvRssi;
    private TextView tvDistance;
    private TextView tvConfidence;
    private TextView tvTrend;
    private TextView tvObservations;
    private TextView tvRangeStatus;
    private TextView tvLiveStatus;
    private Button btnGenerateReport;
    private boolean isCapturingSnapshot = false;

    @Override
    protected void onCreate(
            Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        EdgeToEdge.enable(this);

        setContentView(
                R.layout.activity_potential_harmful
        );
        tvRisk =
                findViewById(R.id.tvRisk);

        tvRssi =
                findViewById(R.id.tvRssi);

        tvDistance =
                findViewById(R.id.tvDistance);

        tvConfidence =
                findViewById(R.id.tvConfidence);

        tvTrend =
                findViewById(R.id.tvTrend);

        tvObservations =
                findViewById(R.id.tvObservations);

        tvRangeStatus =
                findViewById(R.id.tvRangeStatus);

        tvLiveStatus =
                findViewById(R.id.tvLiveStatus);

        btnGenerateReport =
                findViewById(R.id.btnGenerateReport);

        btnGenerateReport.setOnClickListener(v -> generateReportWithMapSnapshot());

        deviceIdentifier =
                getIntent().getStringExtra(
                        "deviceIdentifier"
                );

        trackedDevice =
                findTrackedDevice();

        updateTargetDashboard();

        fusedLocationClient =
                LocationServices
                        .getFusedLocationProviderClient(
                                this
                        );

        SupportMapFragment mapFragment =
                (SupportMapFragment)
                        getSupportFragmentManager()
                                .findFragmentById(
                                        R.id.map
                                );

        if (mapFragment != null) {

            mapFragment.getMapAsync(this);
        }
    }

    private void generateReportWithMapSnapshot() {
        if (deviceIdentifier == null) {
            Toast.makeText(this, "Device identifier unavailable", Toast.LENGTH_SHORT).show();
            return;
        }

        if (isCapturingSnapshot) {
            return;
        }

        if (googleMap != null) {
            isCapturingSnapshot = true;
            btnGenerateReport.setEnabled(false);
            btnGenerateReport.setText("CAPTURING MAP SNAPSHOT...");

            // Safety timeout to avoid hanging if snapshot fails to return
            Handler timeoutHandler = new Handler(getMainLooper());
            Runnable timeoutRunnable = () -> {
                if (isCapturingSnapshot) {
                    isCapturingSnapshot = false;
                    btnGenerateReport.setEnabled(true);
                    btnGenerateReport.setText("GENERATE INVESTIGATION REPORT");
                    launchReportActivity(null);
                }
            };
            timeoutHandler.postDelayed(timeoutRunnable, 3000);

            try {
                googleMap.snapshot(bitmap -> {
                    timeoutHandler.removeCallbacks(timeoutRunnable);
                    isCapturingSnapshot = false;
                    btnGenerateReport.setEnabled(true);
                    btnGenerateReport.setText("GENERATE INVESTIGATION REPORT");
                    launchReportActivity(bitmap);
                });
            } catch (Exception e) {
                timeoutHandler.removeCallbacks(timeoutRunnable);
                isCapturingSnapshot = false;
                btnGenerateReport.setEnabled(true);
                btnGenerateReport.setText("GENERATE INVESTIGATION REPORT");
                launchReportActivity(null);
            }
        } else {
            launchReportActivity(null);
        }
    }

    private void launchReportActivity(Bitmap snapshotBitmap) {
        ReportSnapshotHolder.setSnapshot(snapshotBitmap);
        Intent intent = new Intent(PotentialHarmfulActivity.this, DeviceReportActivity.class);
        intent.putExtra("deviceIdentifier", deviceIdentifier);
        startActivity(intent);
    }

    private DeviceModel findTrackedDevice() {

        if (deviceIdentifier == null ||
                MainActivity.deviceList == null) {

            return null;
        }

        for (DeviceModel device :
                MainActivity.deviceList) {

            if (deviceIdentifier.equals(
                    device.getMacAddress())) {

                return device;
            }
        }

        return null;
    }

    @Override
    public void onMapReady(
            @NonNull GoogleMap map) {

        googleMap = map;

        googleMap.setMapType(
                GoogleMap.MAP_TYPE_SATELLITE
        );

        if (trackedDevice != null) {

            Toast.makeText(
                    this,
                    "Tracking: "
                            + trackedDevice.getMacAddress(),
                    Toast.LENGTH_SHORT
            ).show();

        } else {

            Toast.makeText(
                    this,
                    "BLE device not found",
                    Toast.LENGTH_SHORT
            ).show();
        }

        drawHistoricalTracking();

        enableLocation();
    }

    // =========================================================
    // LIVE TARGET DASHBOARD
    // =========================================================

    private void updateTargetDashboard() {

        if (trackedDevice == null) {
            return;
        }

        trackedDevice.updateRiskAssessment();

        String risk =
                trackedDevice.getRiskLevel();

        int rssi =
                trackedDevice.getLatestRssi();

        double distance =
                trackedDevice.getEstimatedDistance();

        String confidence =
                trackedDevice.getDistanceConfidence();

        String trend =
                trackedDevice.getRssiTrend();

        int observations =
                trackedDevice
                        .getTargetLocationHistory()
                        .size();

        // RISK
        tvRisk.setText(risk);

        if ("CRITICAL".equals(risk)) {

            tvRisk.setTextColor(
                    android.graphics.Color.rgb(
                            255,
                            50,
                            50
                    )
            );

        } else if ("HIGH".equals(risk)) {

            tvRisk.setTextColor(
                    android.graphics.Color.rgb(
                            255,
                            140,
                            0
                    )
            );

        } else if ("MEDIUM".equals(risk)) {

            tvRisk.setTextColor(
                    android.graphics.Color.YELLOW
            );

        } else {

            tvRisk.setTextColor(
                    android.graphics.Color.WHITE
            );
        }

        // RSSI
        tvRssi.setText(
                rssi + " dBm"
        );

        // DISTANCE
        if (distance >= 0) {

            tvDistance.setText(
                    String.format(
                            "%.1f m",
                            distance
                    )
            );

        } else {

            tvDistance.setText(
                    "UNAVAILABLE"
            );
        }

        // CONFIDENCE
        if (confidence == null
                || confidence.isEmpty()) {

            tvConfidence.setText(
                    "UNKNOWN"
            );

        } else {

            tvConfidence.setText(
                    confidence
            );
        }

        // TREND
        if (trend == null
                || trend.isEmpty()) {

            tvTrend.setText(
                    "UNKNOWN"
            );

        } else if ("APPROACHING".equals(trend)) {

            tvTrend.setText(
                    "↑ APPROACHING"
            );

        } else if ("MOVING AWAY".equals(trend)) {

            tvTrend.setText(
                    "↓ MOVING AWAY"
            );

        } else {

            tvTrend.setText(
                    "→ " + trend
            );
        }

        // OBSERVATIONS
        tvObservations.setText(
                String.valueOf(observations)
        );

        // RANGE STATUS
        if (distance > 0) {

            tvRangeStatus.setText(
                    "● RANGE ACTIVE  •  LIVE ESTIMATE"
            );

            tvRangeStatus.setTextColor(
                    android.graphics.Color.rgb(
                            0,
                            230,
                            118
                    )
            );

        } else {

            tvRangeStatus.setText(
                    "○ RANGE UNAVAILABLE  •  CALIBRATION NEEDED"
            );

            tvRangeStatus.setTextColor(
                    android.graphics.Color.rgb(
                            255,
                            193,
                            7
                    )
            );
        }
    }

    // =========================================================
    // HISTORICAL TRACKING
    // =========================================================

    private void drawHistoricalTracking() {

        drawUserPath();

        drawHistoricalTargetRanges();
    }

    // =========================================================
    // USER TRAVEL PATH
    // =========================================================

    private void drawUserPath() {

        List<UserLocationPoint> history =
                MainActivity.userLocationHistory;

        if (history == null ||
                history.size() < 2) {

            return;
        }

        List<LatLng> path =
                new ArrayList<>();

        for (UserLocationPoint point :
                history) {

            path.add(
                    new LatLng(
                            point.getLatitude(),
                            point.getLongitude()
                    )
            );
        }

        userPathPolyline =
                googleMap.addPolyline(
                        new PolylineOptions()
                                .addAll(path)
                                .width(8f)
                );
    }

    // =========================================================
    // HISTORICAL TARGET AREAS
    // =========================================================

    private void drawHistoricalTargetRanges() {

        if (trackedDevice == null) {
            return;
        }

        List<TargetLocationPoint> history =
                trackedDevice
                        .getTargetLocationHistory();

        if (history == null ||
                history.isEmpty()) {

            return;
        }

        for (TargetLocationPoint point :
                history) {

            double distance =
                    point.getEstimatedDistance();

            if (distance <= 0) {
                continue;
            }

            LatLng position =
                    new LatLng(
                            point.getLatitude(),
                            point.getLongitude()
                    );

            Circle circle =
                    googleMap.addCircle(
                            new CircleOptions()
                                    .center(position)
                                    .radius(distance)
                                    .strokeWidth(2f)
                                    .fillColor(
                                            android.graphics.Color.argb(
                                                    30,
                                                    255,
                                                    0,
                                                    0
                                            )
                                    )
                    );

            historicalRangeCircles.add(
                    circle
            );
        }
    }

    // =========================================================
    // LOCATION PERMISSION
    // =========================================================

    private void enableLocation() {

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
                    LOCATION_PERMISSION_REQUEST
            );

            return;
        }

        googleMap.setMyLocationEnabled(true);

        startLocationUpdates();
    }

    // =========================================================
    // LIVE LOCATION
    // =========================================================

    private void startLocationUpdates() {

        LocationRequest locationRequest =
                new LocationRequest.Builder(
                        Priority.PRIORITY_HIGH_ACCURACY,
                        2000
                )
                        .setMinUpdateIntervalMillis(
                                1000
                        )
                        .build();

        locationCallback =
                new LocationCallback() {

                    @Override
                    public void onLocationResult(
                            @NonNull LocationResult
                                    locationResult) {

                        for (Location location :
                                locationResult
                                        .getLocations()) {

                            updateCurrentLocation(
                                    location
                            );
                        }
                    }
                };

        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.ACCESS_FINE_LOCATION
        ) != PackageManager.PERMISSION_GRANTED
                &&
                ActivityCompat.checkSelfPermission(
                        this,
                        Manifest.permission.ACCESS_COARSE_LOCATION
                ) != PackageManager.PERMISSION_GRANTED) {

            return;
        }

        fusedLocationClient
                .requestLocationUpdates(
                        locationRequest,
                        locationCallback,
                        getMainLooper()
                );
    }

    // =========================================================
    // UPDATE CURRENT LOCATION
    // =========================================================

    private void updateCurrentLocation(
            Location location) {

        if (googleMap == null) {
            return;
        }

        LatLng currentPosition =
                new LatLng(
                        location.getLatitude(),
                        location.getLongitude()
                );

        if (currentLocationMarker == null) {

            currentLocationMarker =
                    googleMap.addMarker(
                            new MarkerOptions()
                                    .position(
                                            currentPosition
                                    )
                                    .title(
                                            "Your Location"
                                    )
                    );

        } else {

            currentLocationMarker
                    .setPosition(
                            currentPosition
                    );
        }

        drawLatestLiveRange(
                currentPosition
        );
        updateTargetDashboard();
        if (firstLocationUpdate) {

            googleMap.animateCamera(
                    CameraUpdateFactory
                            .newLatLngZoom(
                                    currentPosition,
                                    18f
                            )
            );

            firstLocationUpdate = false;
        }
    }

    // =========================================================
    // LIVE TARGET RANGE
    // =========================================================

    private void drawLatestLiveRange(
            LatLng currentPosition) {

        if (trackedDevice == null) {
            return;
        }

        double distance =
                trackedDevice
                        .getEstimatedDistance();

        if (distance <= 0) {
            return;
        }

        if (latestLiveRangeCircle != null) {

            latestLiveRangeCircle.remove();
        }

        latestLiveRangeCircle =
                googleMap.addCircle(
                        new CircleOptions()
                                .center(
                                        currentPosition
                                )
                                .radius(distance)
                                .strokeWidth(3f)
                                .fillColor(
                                        android.graphics.Color.argb(
                                                40,
                                                255,
                                                0,
                                                0
                                        )
                                )
                );

        drawDottedRange(
                currentPosition,
                distance
        );
    }

    // =========================================================
    // DOTTED RANGE
    // =========================================================

    private void drawDottedRange(
            LatLng center,
            double radius) {

        for (Polyline line :
                dottedRangeLines) {

            line.remove();
        }

        dottedRangeLines.clear();

        int segments = 72;

        for (int i = 0;
             i < segments;
             i++) {

            double startAngle =
                    Math.toRadians(
                            i * 5.0
                    );

            double endAngle =
                    Math.toRadians(
                            (i * 5.0) + 2.5
                    );

            LatLng start =
                    calculateOffset(
                            center,
                            radius,
                            startAngle
                    );

            LatLng end =
                    calculateOffset(
                            center,
                            radius,
                            endAngle
                    );

            Polyline line =
                    googleMap.addPolyline(
                            new PolylineOptions()
                                    .add(
                                            start,
                                            end
                                    )
                                    .width(4f)
                    );

            dottedRangeLines.add(line);
        }
    }

    // =========================================================
    // CALCULATE POINT ON CIRCLE
    // =========================================================

    private LatLng calculateOffset(
            LatLng center,
            double distanceMeters,
            double angleRadians) {

        final double earthRadius =
                6371000.0;

        double latitudeRadians =
                Math.toRadians(
                        center.latitude
                );

        double longitudeRadians =
                Math.toRadians(
                        center.longitude
                );

        double newLatitude =
                Math.asin(
                        Math.sin(
                                latitudeRadians
                        )
                                * Math.cos(
                                distanceMeters
                                        / earthRadius
                        )
                                +
                                Math.cos(
                                        latitudeRadians
                                )
                                        * Math.sin(
                                        distanceMeters
                                                / earthRadius
                                )
                                        * Math.cos(
                                        angleRadians
                                )
                );

        double newLongitude =
                longitudeRadians
                        +
                        Math.atan2(
                                Math.sin(
                                        angleRadians
                                )
                                        * Math.sin(
                                        distanceMeters
                                                / earthRadius
                                )
                                        * Math.cos(
                                        latitudeRadians
                                ),
                                Math.cos(
                                        distanceMeters
                                                / earthRadius
                                )
                                        -
                                        Math.sin(
                                                latitudeRadians
                                        )
                                                * Math.sin(
                                                newLatitude
                                        )
                        );

        return new LatLng(
                Math.toDegrees(
                        newLatitude
                ),
                Math.toDegrees(
                        newLongitude
                )
        );
    }

    // =========================================================
    // PERMISSION RESULT
    // =========================================================

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            @NonNull String[] permissions,
            @NonNull int[] grantResults) {

        super.onRequestPermissionsResult(
                requestCode,
                permissions,
                grantResults
        );

        if (requestCode ==
                LOCATION_PERMISSION_REQUEST) {

            if (grantResults.length > 0
                    &&
                    grantResults[0]
                            == PackageManager
                            .PERMISSION_GRANTED) {

                enableLocation();

            } else {

                Toast.makeText(
                        this,
                        "Location permission is required for tracking.",
                        Toast.LENGTH_LONG
                ).show();
            }
        }
    }

    // =========================================================
    // CLEANUP
    // =========================================================

    @Override
    protected void onDestroy() {

        super.onDestroy();

        if (fusedLocationClient != null
                && locationCallback != null) {

            if (ActivityCompat.checkSelfPermission(
                    this,
                    Manifest.permission
                            .ACCESS_FINE_LOCATION
            ) == PackageManager
                    .PERMISSION_GRANTED
                    ||
                    ActivityCompat.checkSelfPermission(
                            this,
                            Manifest.permission
                                    .ACCESS_COARSE_LOCATION
                    ) == PackageManager
                            .PERMISSION_GRANTED) {

                fusedLocationClient
                        .removeLocationUpdates(
                                locationCallback
                        );
            }
        }
    }
}