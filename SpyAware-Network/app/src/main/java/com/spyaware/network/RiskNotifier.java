package com.spyaware.network;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Notifies the user once when an app's risk crosses into HIGH or CRITICAL,
 * not on every poll while it stays there. Tapping the notification opens
 * the app to the dashboard.
 */
public class RiskNotifier {

    private static final String CHANNEL_ID = "spyaware_risk_alerts";
    private static final int NOTIFICATION_ID_BASE = 1000;

    // Tracks the highest band we've already notified about, per app, this session.
    private static final Map<String, RiskScorer.Band> notifiedBands = new HashMap<>();

    public static void init(Context context) {
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Risk Alerts", NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Alerts when an app's network behavior looks suspicious");
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.createNotificationChannel(channel);
        }
    }

    public static void resetSession() {
        notifiedBands.clear();
    }

    public static void checkAndNotify(Context context, List<RiskScorer.AppRisk> risks) {
        for (RiskScorer.AppRisk risk : risks) {
            if (risk.band != RiskScorer.Band.HIGH && risk.band != RiskScorer.Band.CRITICAL) {
                continue;
            }

            RiskScorer.Band alreadyNotified = notifiedBands.get(risk.appName);
            boolean shouldNotify = alreadyNotified == null || isEscalation(alreadyNotified, risk.band);

            if (shouldNotify) {
                notifiedBands.put(risk.appName, risk.band);
                sendNotification(context, risk);
            }
        }
    }

    private static boolean isEscalation(RiskScorer.Band previous, RiskScorer.Band current) {
        return rank(current) > rank(previous);
    }

    private static int rank(RiskScorer.Band b) {
        switch (b) {
            case CRITICAL: return 3;
            case HIGH: return 2;
            case MEDIUM: return 1;
            default: return 0;
        }
    }

    private static void sendNotification(Context context, RiskScorer.AppRisk risk) {
        String title = risk.band == RiskScorer.Band.CRITICAL
                ? "Critical risk: " + risk.appName
                : "High risk: " + risk.appName;

        StringBuilder body = new StringBuilder();
        body.append(risk.score).append("/100. ");
        if (!risk.findings.isEmpty()) {
            body.append(risk.findings.get(0).detail);
        }

        Intent openIntent = new Intent(context, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent pendingIntent = PendingIntent.getActivity(context, risk.appName.hashCode(), openIntent, flags);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(body.toString())
                .setStyle(new NotificationCompat.BigTextStyle().bigText(body.toString()))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent);

        try {
            NotificationManagerCompat.from(context)
                    .notify(NOTIFICATION_ID_BASE + risk.appName.hashCode(), builder.build());
        } catch (SecurityException e) {
            // Notification permission not granted -- fail silently, the
            // in-app dashboard still shows the same information.
        }
    }
}