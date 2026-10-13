package com.spyaware.network;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Loads detection thresholds from assets/config.json once at startup.
 * Every value here has a hardcoded fallback matching the original
 * constants, so a missing or malformed file never changes behavior --
 * it just means the defaults documented in this class are used instead
 * of the file's overrides.
 */
public class DetectionConfig {

    private static final String TAG = "DetectionConfig";
    private static DetectionConfig instance;

    // ---- High upload ----
    public long highUploadBytesThreshold = 200_000;
    public double highUploadRatioThreshold = 2.0;
    public long highUploadMinBytesForRatioCheck = 20_000;

    // ---- Repeated destination ----
    public int repeatedDestinationThreshold = 8;

    // ---- Periodicity ----
    public int periodicMinSamples = 3;
    public long periodicToleranceMs = 3_000;
    public long periodicMinAvgGapMs = 2_000;

    // ---- Background communication ----
    public long backgroundBytesThreshold = 100_000;

    // ---- DNS reputation ----
    public double dnsEntropyThreshold = 3.5;
    public int dnsMinLabelLength = 10;
    public int dnsExcessiveQueryThreshold = 25;

    // ---- Risk scoring ----
    public double riskBasePointsPerWeight = 10;
    public double riskDiminishingFactor = 0.6;
    public int riskCriticalThreshold = 75;
    public int riskHighThreshold = 50;
    public int riskMediumThreshold = 20;

    private DetectionConfig() {}

    public static synchronized DetectionConfig getInstance() {
        if (instance == null) {
            instance = new DetectionConfig(); // defaults until init() is called
        }
        return instance;
    }

    /** Call once at app/service startup. Safe to call multiple times. */
    public static synchronized void init(Context context) {
        DetectionConfig cfg = getInstance();
        try {
            StringBuilder sb = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    context.getAssets().open("config.json"), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) sb.append(line);
            }

            JSONObject root = new JSONObject(sb.toString());

            JSONObject highUpload = root.optJSONObject("highUpload");
            if (highUpload != null) {
                cfg.highUploadBytesThreshold = highUpload.optLong("bytesThreshold", cfg.highUploadBytesThreshold);
                cfg.highUploadRatioThreshold = highUpload.optDouble("ratioThreshold", cfg.highUploadRatioThreshold);
                cfg.highUploadMinBytesForRatioCheck = highUpload.optLong("minBytesForRatioCheck", cfg.highUploadMinBytesForRatioCheck);
            }

            JSONObject repeatedDest = root.optJSONObject("repeatedDestination");
            if (repeatedDest != null) {
                cfg.repeatedDestinationThreshold = repeatedDest.optInt("connectionCountThreshold", cfg.repeatedDestinationThreshold);
            }

            JSONObject periodicity = root.optJSONObject("periodicity");
            if (periodicity != null) {
                cfg.periodicMinSamples = periodicity.optInt("minSamples", cfg.periodicMinSamples);
                cfg.periodicToleranceMs = periodicity.optLong("toleranceMs", cfg.periodicToleranceMs);
                cfg.periodicMinAvgGapMs = periodicity.optLong("minAvgGapMs", cfg.periodicMinAvgGapMs);
            }

            JSONObject background = root.optJSONObject("backgroundCommunication");
            if (background != null) {
                cfg.backgroundBytesThreshold = background.optLong("bytesThreshold", cfg.backgroundBytesThreshold);
            }

            JSONObject dns = root.optJSONObject("dnsReputation");
            if (dns != null) {
                cfg.dnsEntropyThreshold = dns.optDouble("entropyThreshold", cfg.dnsEntropyThreshold);
                cfg.dnsMinLabelLength = dns.optInt("minLabelLength", cfg.dnsMinLabelLength);
                cfg.dnsExcessiveQueryThreshold = dns.optInt("excessiveQueryThreshold", cfg.dnsExcessiveQueryThreshold);
            }

            JSONObject risk = root.optJSONObject("riskScoring");
            if (risk != null) {
                cfg.riskBasePointsPerWeight = risk.optDouble("basePointsPerWeight", cfg.riskBasePointsPerWeight);
                cfg.riskDiminishingFactor = risk.optDouble("diminishingFactor", cfg.riskDiminishingFactor);
                cfg.riskCriticalThreshold = risk.optInt("criticalThreshold", cfg.riskCriticalThreshold);
                cfg.riskHighThreshold = risk.optInt("highThreshold", cfg.riskHighThreshold);
                cfg.riskMediumThreshold = risk.optInt("mediumThreshold", cfg.riskMediumThreshold);
            }

            Log.i(TAG, "Detection config loaded from assets/config.json");
        } catch (Exception e) {
            Log.w(TAG, "Could not load config.json, using built-in defaults", e);
            // cfg already holds the hardcoded defaults declared above -- nothing more to do.
        }
    }
}