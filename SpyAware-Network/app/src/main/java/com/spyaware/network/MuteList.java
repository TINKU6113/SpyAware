package com.spyaware.network;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

/**
 * Persists a simple set of app names the user has chosen to exclude from
 * behavioral findings, risk scoring, and notifications. Muting an app does
 * NOT stop capturing its traffic (bytes/connections still count toward
 * totals) -- it only suppresses BehaviorAnalyzer findings for it, so the
 * user can quiet a known-noisy app without losing overall visibility.
 */
public class MuteList {

    private static final String PREFS_NAME = "spyaware_mutelist";
    private static final String KEY_MUTED_APPS = "muted_apps";

    private static SharedPreferences prefs;

    public static synchronized void init(Context context) {
        if (prefs == null) {
            prefs = context.getApplicationContext()
                    .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        }
    }

    public static synchronized boolean isMuted(String appName) {
        if (prefs == null) return false;
        return prefs.getStringSet(KEY_MUTED_APPS, new HashSet<>()).contains(appName);
    }

    public static synchronized void setMuted(String appName, boolean muted) {
        if (prefs == null) return;
        Set<String> current = new HashSet<>(prefs.getStringSet(KEY_MUTED_APPS, new HashSet<>()));
        if (muted) current.add(appName); else current.remove(appName);
        prefs.edit().putStringSet(KEY_MUTED_APPS, current).apply();
    }

    public static synchronized Set<String> getMutedApps() {
        if (prefs == null) return new HashSet<>();
        return new HashSet<>(prefs.getStringSet(KEY_MUTED_APPS, new HashSet<>()));
    }
}