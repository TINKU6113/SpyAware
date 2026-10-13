package com.spyaware.network;

import java.util.HashMap;
import java.util.Map;

/**
 * Lightweight heuristics over queried domain names. Thresholds are supplied
 * by the caller (from DetectionConfig) rather than hardcoded here.
 */
public class DnsReputationAnalyzer {

    public static boolean looksLikeDga(String hostname, double entropyThreshold, int minLabelLen) {
        if (hostname == null) return false;
        for (String label : hostname.split("\\.")) {
            if (label.length() >= minLabelLen && entropy(label) >= entropyThreshold) {
                return true;
            }
        }
        return false;
    }

    private static double entropy(String s) {
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) freq.merge(c, 1, Integer::sum);

        double e = 0;
        int n = s.length();
        for (int count : freq.values()) {
            double p = (double) count / n;
            e -= p * (Math.log(p) / Math.log(2));
        }
        return e;
    }
}