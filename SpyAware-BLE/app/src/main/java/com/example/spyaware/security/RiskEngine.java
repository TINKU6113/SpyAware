package com.example.spyaware.security;

import com.example.spyaware.model.DeviceModel;

public class RiskEngine {

    // =========================================================
    // RISK LEVELS
    // =========================================================

    public static final String LOW = "LOW";
    public static final String MEDIUM = "MEDIUM";
    public static final String HIGH = "HIGH";
    public static final String CRITICAL = "CRITICAL";


    // =========================================================
    // CALCULATE RISK SCORE
    // =========================================================

    public static int calculateRiskScore(
            DeviceModel device) {

        if (device == null) {
            return 0;
        }

        int score = 0;


        // =====================================================
        // 1. DEVICE CLASSIFICATION
        // =====================================================

        if (device.isUnknownDevice()) {

            score += 10;

        } else if (device.isKnownDevice()) {

            score -= 20;
        }


        // =====================================================
        // 2. PROXIMITY
        // =====================================================

        double distance =
                device.getEstimatedDistance();

        if (distance >= 0) {

            if (distance < 1) {

                score += 25;

            } else if (distance < 2) {

                score += 18;

            } else if (distance < 5) {

                score += 12;

            } else if (distance < 10) {

                score += 7;

            } else if (distance < 15) {

                score += 3;
            }
        }


        // =====================================================
        // 3. PERSISTENCE
        // =====================================================

        String persistence =
                device.getPersistenceState();

        if ("PERSISTENT".equals(persistence)) {

            score += 20;

        } else if ("RECURRING".equals(persistence)) {

            score += 10;

        } else if ("OCCASIONAL".equals(persistence)) {

            score += 5;
        }


        // =====================================================
        // 4. RSSI TREND
        // =====================================================

        String trend =
                device.getRssiTrend();

        if ("APPROACHING".equals(trend)) {

            score += 15;

        } else if ("STABLE".equals(trend)) {

            score += 3;
        }


        // =====================================================
        // 5. REPEATED PRESENCE
        // =====================================================

        int sessions =
                device.getSessionCount();

        if (sessions >= 4) {

            score += 10;

        } else if (sessions >= 2) {

            score += 5;
        }


        // =====================================================
        // LIMIT SCORE
        // =====================================================

        if (score < 0) {
            score = 0;
        }

        if (score > 100) {
            score = 100;
        }

        return score;
    }


    // =========================================================
    // CONVERT SCORE → RISK LEVEL
    // =========================================================

    public static String getRiskLevel(int score) {

        if (score >= 75) {

            return CRITICAL;

        } else if (score >= 50) {

            return HIGH;

        } else if (score >= 25) {

            return MEDIUM;

        } else {

            return LOW;
        }
    }
}