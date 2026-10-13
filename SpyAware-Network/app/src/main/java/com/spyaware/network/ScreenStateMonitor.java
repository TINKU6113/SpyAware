package com.spyaware.network;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.PowerManager;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tracks whether the device screen is currently on or off, so PacketLog can
 * tag traffic that happens while nobody is looking at the phone.
 */
public class ScreenStateMonitor {

    private static final AtomicBoolean screenOn = new AtomicBoolean(true);
    private static BroadcastReceiver receiver;
    private static boolean initialized = false;

    public static synchronized void init(Context context) {
        if (initialized) return;
        initialized = true;

        Context appContext = context.getApplicationContext();

        // Seed with the real current state instead of assuming "on"
        PowerManager pm = (PowerManager) appContext.getSystemService(Context.POWER_SERVICE);
        if (pm != null) {
            screenOn.set(pm.isInteractive());
        }

        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context ctx, Intent intent) {
                if (Intent.ACTION_SCREEN_OFF.equals(intent.getAction())) {
                    screenOn.set(false);
                } else if (Intent.ACTION_SCREEN_ON.equals(intent.getAction())) {
                    screenOn.set(true);
                }
            }
        };

        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_SCREEN_ON);
        filter.addAction(Intent.ACTION_SCREEN_OFF);
        // Note: SCREEN_ON/OFF are protected system broadcasts that cannot be
        // sent by other apps, so RECEIVER_NOT_EXPORTED context isn't required
        // the way it is for our own STATUS_UPDATE broadcast, but we set it
        // anyway on API 33+ for consistency and to satisfy manifest scanners.
        appContext.registerReceiver(receiver, filter);
    }

    public static void shutdown(Context context) {
        if (!initialized) return;
        try {
            context.getApplicationContext().unregisterReceiver(receiver);
        } catch (Exception ignored) {
            // already unregistered, fine
        }
        initialized = false;
    }

    public static boolean isScreenOn() {
        return screenOn.get();
    }
}