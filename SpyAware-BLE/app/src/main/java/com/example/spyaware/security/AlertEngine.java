package com.example.spyaware.security;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.os.VibratorManager;

import androidx.core.app.NotificationCompat;

import com.example.spyaware.R;
import com.example.spyaware.activities.MainActivity;
import com.example.spyaware.model.DeviceModel;

import java.util.HashMap;
import java.util.Map;

public class AlertEngine {

    // =========================================================
    // ALERT THRESHOLDS
    // =========================================================

    private static final int HIGH_THRESHOLD = 50;
    private static final int CRITICAL_THRESHOLD = 75;

    // =========================================================
    // ALERT COOLDOWN
    // =========================================================

    private static final long ALERT_COOLDOWN_MS =
            60 * 1000;

    // =========================================================
    // NOTIFICATION CHANNEL
    // =========================================================

    private static final String CHANNEL_ID =
            "spyaware_alerts";

    private static final String CHANNEL_NAME =
            "SpyAware Security Alerts";

    // =========================================================
    // LAST ALERT TIME
    // =========================================================

    private final Map<String, Long> lastAlertTimes =
            new HashMap<>();

    // =========================================================
    // NOTIFICATION ID
    // =========================================================

    private int notificationId = 1000;

    // =========================================================
    // CHECK DEVICE
    // =========================================================

    public void evaluateDevice(
            Context context,
            DeviceModel device) {

        if (context == null || device == null) {
            return;
        }

        int score =
                device.getRiskScore();

        String riskLevel =
                device.getRiskLevel();

        // -----------------------------------------------------
        // LOW / MEDIUM
        // -----------------------------------------------------

        if (score < HIGH_THRESHOLD) {
            return;
        }

        // -----------------------------------------------------
        // Check cooldown
        // -----------------------------------------------------

        String identifier =
                device.getBleFingerprint();

        if (identifier == null ||
                identifier.isEmpty() ||
                identifier.equals("Unknown")) {

            identifier =
                    device.getMacAddress();
        }

        long currentTime =
                System.currentTimeMillis();

        Long lastAlert =
                lastAlertTimes.get(identifier);

        if (lastAlert != null) {

            long elapsed =
                    currentTime - lastAlert;

            if (elapsed < ALERT_COOLDOWN_MS) {
                return;
            }
        }

        // -----------------------------------------------------
        // Record alert
        // -----------------------------------------------------

        lastAlertTimes.put(
                identifier,
                currentTime
        );

        // -----------------------------------------------------
        // Send alert
        // -----------------------------------------------------

        sendNotification(
                context,
                device,
                score,
                riskLevel
        );

        vibrate(context, riskLevel);
    }

    // =========================================================
    // SEND NOTIFICATION
    // =========================================================

    private void sendNotification(
            Context context,
            DeviceModel device,
            int score,
            String riskLevel) {

        createNotificationChannel(context);

        Intent intent =
                new Intent(
                        context,
                        MainActivity.class
                );

        intent.setFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK |
                        Intent.FLAG_ACTIVITY_CLEAR_TOP
        );

        PendingIntent pendingIntent =
                PendingIntent.getActivity(
                        context,
                        0,
                        intent,
                        PendingIntent.FLAG_UPDATE_CURRENT |
                                PendingIntent.FLAG_IMMUTABLE
                );

        String title;

        if (RiskEngine.CRITICAL.equals(riskLevel)) {

            title =
                    "CRITICAL BLE DEVICE DETECTED";

        } else {

            title =
                    "HIGH RISK BLE DEVICE DETECTED";
        }

        String message =
                device.getDeviceName()
                        + "\nRisk: "
                        + riskLevel
                        + " ("
                        + score
                        + "/100)"
                        + "\nDistance: "
                        + String.format(
                        java.util.Locale.US,
                        "%.1f m",
                        device.getEstimatedDistance()
                );

        NotificationCompat.Builder builder =
                new NotificationCompat.Builder(
                        context,
                        CHANNEL_ID
                )
                        .setSmallIcon(
                                R.drawable.ic_launcher_foreground
                        )
                        .setContentTitle(title)
                        .setContentText(
                                "Risk "
                                        + score
                                        + "/100 - "
                                        + device.getDeviceName()
                        )
                        .setStyle(
                                new NotificationCompat.BigTextStyle()
                                        .bigText(message)
                        )
                        .setPriority(
                                NotificationCompat.PRIORITY_HIGH
                        )
                        .setAutoCancel(true)
                        .setContentIntent(
                                pendingIntent
                        );

        NotificationManager manager =
                (NotificationManager)
                        context.getSystemService(
                                Context.NOTIFICATION_SERVICE
                        );

        if (manager != null) {

            manager.notify(
                    notificationId++,
                    builder.build()
            );
        }
    }

    // =========================================================
    // NOTIFICATION CHANNEL
    // =========================================================

    private void createNotificationChannel(
            Context context) {

        if (Build.VERSION.SDK_INT <
                Build.VERSION_CODES.O) {

            return;
        }

        NotificationManager manager =
                context.getSystemService(
                        NotificationManager.class
                );

        if (manager == null) {
            return;
        }

        NotificationChannel channel =
                new NotificationChannel(
                        CHANNEL_ID,
                        CHANNEL_NAME,
                        NotificationManager.IMPORTANCE_HIGH
                );

        channel.setDescription(
                "Security alerts generated by SpyAware"
        );

        manager.createNotificationChannel(
                channel
        );
    }

    // =========================================================
    // VIBRATION
    // =========================================================

    private void vibrate(
            Context context,
            String riskLevel) {

        if (Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.S) {

            VibratorManager vibratorManager =
                    (VibratorManager)
                            context.getSystemService(
                                    Context.VIBRATOR_MANAGER_SERVICE
                            );

            if (vibratorManager == null) {
                return;
            }

            Vibrator vibrator =
                    vibratorManager.getDefaultVibrator();

            if (RiskEngine.CRITICAL.equals(
                    riskLevel)) {

                vibrator.vibrate(
                        VibrationEffect.createWaveform(
                                new long[]{
                                        0,
                                        300,
                                        150,
                                        300,
                                        150,
                                        500
                                },
                                -1
                        )
                );

            } else {

                vibrator.vibrate(
                        VibrationEffect.createOneShot(
                                400,
                                VibrationEffect.DEFAULT_AMPLITUDE
                        )
                );
            }

        } else {

            Vibrator vibrator =
                    (Vibrator)
                            context.getSystemService(
                                    Context.VIBRATOR_SERVICE
                            );

            if (vibrator == null) {
                return;
            }

            vibrator.vibrate(400);
        }
    }
}