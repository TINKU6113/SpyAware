package com.example.spyaware.activities;

import android.Manifest;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.location.Location;
import android.os.Bundle;
import android.os.Looper;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;

import com.example.spyaware.R;
import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.model.TargetLocationPoint;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PotentialTargetsMapActivity
        extends AppCompatActivity
        implements OnMapReadyCallback {

    private static final int LOCATION_PERMISSION_REQUEST = 2001;

    private GoogleMap googleMap;

    private FusedLocationProviderClient fusedLocationClient;

    private LocationCallback locationCallback;

    private Marker userMarker;

    private Polyline userPathPolyline;

    private final List<Circle> targetCircles =
            new ArrayList<>();

    private final List<Marker> targetMarkers =
            new ArrayList<>();

    private final List<Polyline> targetHistoryLines =
            new ArrayList<>();

    private final List<LatLng> userPath =
            new ArrayList<>();

    private final Map<String, Integer> deviceColors =
            new HashMap<>();

    private final int[] targetColors = {
            Color.rgb(244, 67, 54),      // Red
            Color.rgb(255, 152, 0),      // Orange
            Color.rgb(156, 39, 176),     // Purple
            Color.rgb(76, 175, 80),      // Green
            Color.rgb(33, 150, 243),     // Blue
            Color.rgb(0, 188, 212),      // Cyan
            Color.rgb(255, 193, 7)       // Amber
    };

    private int nextColorIndex = 0;

    private Location latestUserLocation;

    private TextView tvMapInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_potential_targets_map);

        fusedLocationClient =
                LocationServices.getFusedLocationProviderClient(this);

        tvMapInfo =
                findViewById(R.id.tvMapInfo);

        SupportMapFragment mapFragment =
                (SupportMapFragment)
                        getSupportFragmentManager()
                                .findFragmentById(R.id.targetMap);

        if (mapFragment != null) {
            mapFragment.getMapAsync(this);
        }
    }

    @Override
    public void onMapReady(@NonNull GoogleMap map) {

        googleMap = map;

        googleMap.setMapType(
                GoogleMap.MAP_TYPE_SATELLITE
        );

        googleMap.getUiSettings()
                .setZoomControlsEnabled(true);

        googleMap.getUiSettings()
                .setCompassEnabled(true);

        drawAllPotentialTargets();

        startLocationTracking();
    }

    /**
     * Draw every HIGH / CRITICAL device
     * currently present in MainActivity.deviceList.
     */
    private void drawAllPotentialTargets() {

        if (MainActivity.deviceList == null) {
            return;
        }

        int targetCount = 0;

        for (DeviceModel device :
                MainActivity.deviceList) {

            if (device == null) {
                continue;
            }

            device.updateRiskAssessment();

            String risk =
                    device.getRiskLevel();

            if (!"HIGH".equals(risk)
                    && !"CRITICAL".equals(risk)) {
                continue;
            }

            targetCount++;

            drawTarget(device);
        }

        if (tvMapInfo != null) {

            tvMapInfo.setText(
                    "Potential Targets: "
                            + targetCount
                            + "\n"
                            + "Circles = estimated target range"
            );
        }

        if (targetCount == 0) {

            Toast.makeText(
                    this,
                    "No potential targets detected",
                    Toast.LENGTH_SHORT
            ).show();
        }
    }

    /**
     * Draw one potential target.
     */
    private void drawTarget(
            DeviceModel device
    ) {

        String deviceId =
                device.getMacAddress();

        if (deviceId == null
                || deviceId.isEmpty()) {
            return;
        }

        int color =
                getDeviceColor(deviceId);

        List<TargetLocationPoint> history =
                device.getTargetLocationHistory();

        if (history == null
                || history.isEmpty()) {
            return;
        }

        /*
         * Draw historical estimated ranges.
         */
        for (TargetLocationPoint point :
                history) {

            if (point == null) {
                continue;
            }

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
                                    .strokeColor(
                                            color
                                    )
                                    .fillColor(
                                            Color.argb(
                                                    25,
                                                    Color.red(color),
                                                    Color.green(color),
                                                    Color.blue(color)
                                            )
                                    )
                    );

            targetCircles.add(circle);
        }

        /*
         * Draw estimated historical movement.
         *
         * IMPORTANT:
         * These are observation regions,
         * not exact GPS positions.
         */
        List<LatLng> estimatedPath =
                new ArrayList<>();

        for (TargetLocationPoint point :
                history) {

            if (point == null) {
                continue;
            }

            estimatedPath.add(
                    new LatLng(
                            point.getLatitude(),
                            point.getLongitude()
                    )
            );
        }

        if (estimatedPath.size() >= 2) {

            Polyline line =
                    googleMap.addPolyline(
                            new PolylineOptions()
                                    .addAll(estimatedPath)
                                    .color(color)
                                    .width(4f)
                                    .geodesic(true)
                    );

            targetHistoryLines.add(line);
        }

        /*
         * Latest estimated range.
         */
        TargetLocationPoint latest =
                history.get(history.size() - 1);

        double latestDistance =
                latest.getEstimatedDistance();

        if (latestDistance > 0) {

            LatLng latestPosition =
                    new LatLng(
                            latest.getLatitude(),
                            latest.getLongitude()
                    );

            Circle latestCircle =
                    googleMap.addCircle(
                            new CircleOptions()
                                    .center(
                                            latestPosition
                                    )
                                    .radius(
                                            latestDistance
                                    )
                                    .strokeWidth(5f)
                                    .strokeColor(color)
                                    .fillColor(
                                            Color.argb(
                                                    45,
                                                    Color.red(color),
                                                    Color.green(color),
                                                    Color.blue(color)
                                            )
                                    )
                    );

            targetCircles.add(latestCircle);

            Marker marker =
                    googleMap.addMarker(
                            new MarkerOptions()
                                    .position(
                                            latestPosition
                                    )
                                    .title(
                                            "Potential Target"
                                    )
                                    .snippet(
                                            "Risk: "
                                                    + device.getRiskLevel()
                                                    + " | RSSI: "
                                                    + device.getLatestRssi()
                                                    + " dBm"
                                                    + " | Distance: "
                                                    + String.format(
                                                    "%.1f m",
                                                    latestDistance
                                            )
                                    )
                    );

            if (marker != null) {
                targetMarkers.add(marker);
            }
        }
    }

    /**
     * Give every BLE device a stable
     * colour during this map session.
     */
    private int getDeviceColor(
            String deviceId
    ) {

        if (deviceColors.containsKey(deviceId)) {

            return deviceColors.get(deviceId);
        }

        int color =
                targetColors[
                        nextColorIndex
                                % targetColors.length
                        ];

        nextColorIndex++;

        deviceColors.put(
                deviceId,
                color
        );

        return color;
    }

    /**
     * Start real GPS tracking for the user.
     */
    private void startLocationTracking() {

        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.ACCESS_FINE_LOCATION
        ) != PackageManager.PERMISSION_GRANTED
                &&
                ActivityCompat.checkSelfPermission(
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

        LocationRequest request =
                new LocationRequest.Builder(
                        Priority.PRIORITY_HIGH_ACCURACY,
                        2000
                )
                        .setMinUpdateIntervalMillis(1000)
                        .build();

        locationCallback =
                new LocationCallback() {

                    @Override
                    public void onLocationResult(
                            @NonNull LocationResult result
                    ) {

                        for (Location location :
                                result.getLocations()) {

                            updateUserLocation(
                                    location
                            );
                        }
                    }
                };

        fusedLocationClient.requestLocationUpdates(
                request,
                locationCallback,
                Looper.getMainLooper()
        );
    }

    /**
     * Draw user's real movement path.
     */
    private void updateUserLocation(
            Location location
    ) {

        if (location == null) {
            return;
        }

        latestUserLocation = location;

        LatLng position =
                new LatLng(
                        location.getLatitude(),
                        location.getLongitude()
                );

        userPath.add(position);

        if (userMarker == null) {

            userMarker =
                    googleMap.addMarker(
                            new MarkerOptions()
                                    .position(position)
                                    .title("You")
                    );

            googleMap.animateCamera(
                    CameraUpdateFactory
                            .newLatLngZoom(
                                    position,
                                    18f
                            )
            );

        } else {

            userMarker.setPosition(
                    position
            );
        }

        if (userPathPolyline != null) {
            userPathPolyline.remove();
        }

        userPathPolyline =
                googleMap.addPolyline(
                        new PolylineOptions()
                                .addAll(userPath)
                                .color(
                                        Color.BLUE
                                )
                                .width(7f)
                                .geodesic(true)
                );
    }

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
                LOCATION_PERMISSION_REQUEST) {

            if (grantResults.length > 0
                    && grantResults[0]
                    == PackageManager.PERMISSION_GRANTED) {

                startLocationTracking();

            } else {

                Toast.makeText(
                        this,
                        "Location permission is required for the target map",
                        Toast.LENGTH_LONG
                ).show();
            }
        }
    }

    @Override
    protected void onDestroy() {

        super.onDestroy();

        if (fusedLocationClient != null
                && locationCallback != null) {

            fusedLocationClient
                    .removeLocationUpdates(
                            locationCallback
                    );
        }
    }
}