package com.spyaware.network;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Stage 9: aggregates BehaviorAnalyzer findings per app into a 0-100 score
 * and a LOW/MEDIUM/HIGH/CRITICAL band. Scoring curve and band cutoffs now
 * come from DetectionConfig (assets/config.json).
 */
public class RiskScorer {

    public enum Band { LOW, MEDIUM, HIGH, CRITICAL }

    public static class AppRisk {
        public final String appName;
        public final int score;
        public final Band band;
        public final List<BehaviorAnalyzer.Finding> findings;

        AppRisk(String appName, int score, Band band, List<BehaviorAnalyzer.Finding> findings) {
            this.appName = appName;
            this.score = score;
            this.band = band;
            this.findings = findings;
        }
    }

    public static synchronized List<AppRisk> scoreAll() {
        List<BehaviorAnalyzer.Finding> allFindings = BehaviorAnalyzer.analyze();

        Map<String, List<BehaviorAnalyzer.Finding>> byApp = new HashMap<>();
        for (BehaviorAnalyzer.Finding f : allFindings) {
            byApp.computeIfAbsent(f.appName, k -> new ArrayList<>()).add(f);
        }

        List<AppRisk> results = new ArrayList<>();
        for (Map.Entry<String, List<BehaviorAnalyzer.Finding>> e : byApp.entrySet()) {
            results.add(score(e.getKey(), e.getValue()));
        }

        results.sort((a, b) -> Integer.compare(b.score, a.score));
        return results;
    }

    private static AppRisk score(String appName, List<BehaviorAnalyzer.Finding> findings) {
        DetectionConfig cfg = DetectionConfig.getInstance();

        findings.sort((a, b) -> Integer.compare(b.weight, a.weight));

        double total = 0;
        double diminishFactor = 1.0;
        for (BehaviorAnalyzer.Finding f : findings) {
            total += f.weight * cfg.riskBasePointsPerWeight * diminishFactor;
            diminishFactor *= cfg.riskDiminishingFactor;
        }

        int scoreValue = (int) Math.round(Math.min(100, total));
        return new AppRisk(appName, scoreValue, bandFor(scoreValue, cfg), findings);
    }

    private static Band bandFor(int score, DetectionConfig cfg) {
        if (score >= cfg.riskCriticalThreshold) return Band.CRITICAL;
        if (score >= cfg.riskHighThreshold) return Band.HIGH;
        if (score >= cfg.riskMediumThreshold) return Band.MEDIUM;
        return Band.LOW;
    }

    public static synchronized String getSummary() {
        List<AppRisk> risks = scoreAll();
        if (risks.isEmpty()) {
            return "No risk signals yet.\n";
        }

        StringBuilder sb = new StringBuilder();
        for (AppRisk r : risks) {
            sb.append(String.format(Locale.US, "%s: %d/100 [%s]\n",
                    r.appName, r.score, r.band));
            for (BehaviorAnalyzer.Finding f : r.findings) {
                sb.append("   - ").append(f.detail).append("\n");
            }
        }
        return sb.toString();
    }
}