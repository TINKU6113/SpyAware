package com.example.spyaware.activities;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.spyaware.R;
import com.example.spyaware.model.DeviceModel;

public class DeviceDetailsActivity extends AppCompatActivity {

    private RadarView radarView;
    private TextView tvAnalysisDevice;
    private TextView tvAnalysisRssi;
    private TextView tvAnalysisClassification;
    private TextView tvAnalysisDistance;
    private TextView tvAnalysisProximity;
    private TextView tvAnalysisTrend;

    private Button btnCalibrate;

    private DeviceModel device;

    private boolean isCalibrating = false;

    private int calibrationSamples = 0;
    private int calibrationRssiSum = 0;

    private static final int CALIBRATION_SAMPLE_COUNT = 10;


    // ============================================================
    // PERIODIC UI UPDATE
    // ============================================================

    private final Handler updateHandler =
            new Handler(Looper.getMainLooper());

    private final Runnable updateRunnable =
            new Runnable() {

                @Override
                public void run() {

                    updateDeviceInformation();

                    updateHandler.postDelayed(
                            this,
                            1000
                    );
                }
            };


    // ============================================================
    // ON CREATE
    // ============================================================

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_device);


        // --------------------------------
        // Find UI elements
        // --------------------------------
        radarView =
                findViewById(R.id.radarView);
        tvAnalysisDevice =
                findViewById(R.id.tvAnalysisDevice);

        tvAnalysisRssi =
                findViewById(R.id.tvAnalysisRssi);
        tvAnalysisClassification =
                findViewById(R.id.tvAnalysisClassification);

        tvAnalysisDistance =
                findViewById(R.id.tvAnalysisDistance);

        tvAnalysisProximity =
                findViewById(R.id.tvAnalysisProximity);

        tvAnalysisTrend =
                findViewById(R.id.tvAnalysisTrend);

        btnCalibrate =
                findViewById(R.id.btnCalibrate);


        // --------------------------------
        // Get selected device identifier
        // --------------------------------

        String identifier =
                getIntent().getStringExtra(
                        "deviceIdentifier"
                );

        if (identifier == null) {

            finish();
            return;
        }


        // --------------------------------
        // Find device from MainActivity
        // --------------------------------

        DeviceModel selectedDevice = null;

        if (MainActivity.deviceList != null) {

            for (DeviceModel currentDevice :
                    MainActivity.deviceList) {

                if (currentDevice.getMacAddress() != null
                        && currentDevice
                        .getMacAddress()
                        .equals(identifier)) {

                    selectedDevice = currentDevice;

                    break;
                }
            }
        }


        // --------------------------------
        // Device wasn't found
        // --------------------------------

        if (selectedDevice == null) {

            Toast.makeText(
                    this,
                    "Device not found",
                    Toast.LENGTH_SHORT
            ).show();

            finish();

            return;
        }


        // Keep reference to live DeviceModel
        device = selectedDevice;


        // --------------------------------
        // Initial display
        // --------------------------------

        updateDeviceInformation();


        // --------------------------------
        // Calibration button
        // --------------------------------

        btnCalibrate.setOnClickListener(v -> {

            if (device == null) {
                return;
            }

            if (isCalibrating) {
                return;
            }


            isCalibrating = true;

            calibrationSamples = 0;

            calibrationRssiSum = 0;


            btnCalibrate.setEnabled(false);

            btnCalibrate.setText(
                    "CALIBRATING... 0/"
                            + CALIBRATION_SAMPLE_COUNT
            );


            Toast.makeText(
                    DeviceDetailsActivity.this,
                    "Keep the BLE device approximately 1 metre away",
                    Toast.LENGTH_LONG
            ).show();


            startCalibration();
        });
    }


    // ============================================================
    // RESUME
    // ============================================================

    @Override
    protected void onResume() {

        super.onResume();

        updateHandler.post(
                updateRunnable
        );
    }


    // ============================================================
    // PAUSE
    // ============================================================

    @Override
    protected void onPause() {

        super.onPause();

        updateHandler.removeCallbacks(
                updateRunnable
        );
    }


    // ============================================================
    // START CALIBRATION
    // ============================================================

    private void startCalibration() {

        if (!isCalibrating || device == null) {
            return;
        }


        // Get latest RSSI
        int currentRssi =
                device.getRssi();


        calibrationRssiSum +=
                currentRssi;

        calibrationSamples++;


        // Update button
        btnCalibrate.setText(
                "CALIBRATING... "
                        + calibrationSamples
                        + "/"
                        + CALIBRATION_SAMPLE_COUNT
        );


        // --------------------------------
        // Enough samples?
        // --------------------------------

        if (calibrationSamples >=
                CALIBRATION_SAMPLE_COUNT) {

            finishCalibration();

            return;
        }


        // --------------------------------
        // Next sample after 500 ms
        // --------------------------------

        btnCalibrate.postDelayed(
                this::startCalibration,
                500
        );
    }


    // ============================================================
    // FINISH CALIBRATION
    // ============================================================

    private void finishCalibration() {

        isCalibrating = false;


        // Calculate average RSSI
        int averageRssi =
                calibrationRssiSum
                        / calibrationSamples;


        // Save 1 metre reference RSSI
        device.setCalibrationRssi(
                averageRssi
        );


        // Enable button
        btnCalibrate.setEnabled(true);

        btnCalibrate.setText(
                "CALIBRATE AT 1 METRE"
        );


        Toast.makeText(
                DeviceDetailsActivity.this,
                "Calibration complete: "
                        + averageRssi
                        + " dBm at approximately 1 metre",
                Toast.LENGTH_LONG
        ).show();


        updateDeviceInformation();
    }


    // ============================================================
    // UPDATE DEVICE INFORMATION
    // ============================================================

    private void updateDeviceInformation() {

        if (device == null) {
            return;
        }



        // Device name
        tvAnalysisDevice.setText(
                device.getDeviceName()
        );
        tvAnalysisClassification.setText(
                "Classification: "
                        + device.getDeviceClassification()
        );

        // RSSI
        tvAnalysisRssi.setText(
                "RSSI: "
                        + device.getRssi()
                        + " dBm"
        );
        float distance =
                (float) device.getEstimatedDistance();

        radarView.setDistance(distance);

        // Distance
        tvAnalysisDistance.setText(
                String.format(
                        java.util.Locale.US,
                        "Estimated Distance: %.2f m",
                        device.getEstimatedDistance()
                )
        );


        // Proximity
        tvAnalysisProximity.setText(
                "Proximity: "
                        + device.getProximityState()
        );


        // RSSI trend
        tvAnalysisTrend.setText(
                "Trend: "
                        + device.getRssiTrend()
        );
    }
}