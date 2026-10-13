package com.spyaware.network;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Stage 8 (+ media combination + background communication + DNS reputation):
 * looks across all flows grouped by app and flags behavioral patterns.
 * All thresholds now come from DetectionConfig (assets/config.json), so
 * they can be tuned/documented without recompiling.
 */
public class BehaviorAnalyzer {

    public static class Finding {
        public final String appName;
        public final String signal;
        public final String detail;
        public final int weight;

        Finding(String appName, String signal, String detail, int weight) {
            this.appName = appName;
            this.signal = signal;
            this.detail = detail;
            this.weight = weight;
        }
    }

    public static synchronized List<Finding> analyze() {
        DetectionConfig cfg = DetectionConfig.getInstance();
        List<PacketLog.Flow> flows = PacketLog.getFlows();
        List<Finding> allFindings = new ArrayList<>();

        Map<String, List<PacketLog.Flow>> byApp = new HashMap<>();
        for (PacketLog.Flow f : flows) {
            byApp.computeIfAbsent(f.appName, k -> new ArrayList<>()).add(f);
        }

        for (Map.Entry<String, List<PacketLog.Flow>> entry : byApp.entrySet()) {
            String app = entry.getKey();

            if (MuteList.isMuted(app)) continue;

            List<PacketLog.Flow> appFlows = entry.getValue();

            List<Finding> perApp = new ArrayList<>();
            checkHighUpload(app, appFlows, perApp, cfg);
            checkRepeatedDestination(app, appFlows, perApp, cfg);
            checkPeriodicity(app, appFlows, perApp, cfg);
            checkBackgroundCommunication(app, appFlows, perApp, cfg);
            checkDnsReputation(app, appFlows, perApp, cfg);

            checkMediaTransferCombination(app, appFlows, perApp);

            allFindings.addAll(perApp);
        }

        return allFindings;
    }

    private static void checkHighUpload(String app, List<PacketLog.Flow> flows, List<Finding> out, DetectionConfig cfg) {
        for (PacketLog.Flow f : flows) {
            boolean bigEnough = f.bytesOut > cfg.highUploadBytesThreshold;
            boolean lopsided = f.bytesIn > 0
                    && (double) f.bytesOut / f.bytesIn > cfg.highUploadRatioThreshold;

            if (bigEnough || (lopsided && f.bytesOut > cfg.highUploadMinBytesForRatioCheck)) {
                out.add(new Finding(app, "HIGH_UPLOAD",
                        String.format(Locale.US, "%s sent %s out vs %s in to %s:%d",
                                app, fmt(f.bytesOut), fmt(f.bytesIn), f.dstIp, f.dstPort),
                        bigEnough ? 3 : 2));
            }
        }
    }

    private static void checkRepeatedDestination(String app, List<PacketLog.Flow> flows, List<Finding> out, DetectionConfig cfg) {
        Map<String, Integer> destCounts = new HashMap<>();
        for (PacketLog.Flow f : flows) {
            destCounts.merge(f.dstIp, 1, Integer::sum);
        }
        for (Map.Entry<String, Integer> e : destCounts.entrySet()) {
            if (e.getValue() >= cfg.repeatedDestinationThreshold) {
                out.add(new Finding(app, "REPEATED_DESTINATION",
                        String.format(Locale.US, "%s connected to %s %d times this session",
                                app, e.getKey(), e.getValue()),
                        2));
            }
        }
    }

    private static void checkPeriodicity(String app, List<PacketLog.Flow> flows, List<Finding> out, DetectionConfig cfg) {
        Map<String, List<Long>> startTimesByDest = new HashMap<>();
        for (PacketLog.Flow f : flows) {
            startTimesByDest.computeIfAbsent(f.dstIp, k -> new ArrayList<>()).add(f.firstSeen);
        }

        for (Map.Entry<String, List<Long>> e : startTimesByDest.entrySet()) {
            List<Long> times = e.getValue();
            if (times.size() < cfg.periodicMinSamples) continue;

            times.sort(Long::compareTo);
            List<Long> gaps = new ArrayList<>();
            for (int i = 1; i < times.size(); i++) {
                gaps.add(times.get(i) - times.get(i - 1));
            }

            long avg = 0;
            for (long g : gaps) avg += g;
            avg /= gaps.size();

            boolean consistent = true;
            for (long g : gaps) {
                if (Math.abs(g - avg) > cfg.periodicToleranceMs) {
                    consistent = false;
                    break;
                }
            }

            if (consistent && avg > cfg.periodicMinAvgGapMs) {
                out.add(new Finding(app, "PERIODIC",
                        String.format(Locale.US, "%s contacted %s every ~%.1fs (%d times)",
                                app, e.getKey(), avg / 1000.0, times.size()),
                        3));
            }
        }
    }

    private static void checkBackgroundCommunication(String app, List<PacketLog.Flow> flows, List<Finding> out, DetectionConfig cfg) {
        long totalBackgroundBytes = 0;
        int flowsWithBackground = 0;

        for (PacketLog.Flow f : flows) {
            if (f.hadBackgroundActivity) {
                totalBackgroundBytes += f.backgroundBytes;
                flowsWithBackground++;
            }
        }

        if (totalBackgroundBytes >= cfg.backgroundBytesThreshold) {
            out.add(new Finding(app, "BACKGROUND_COMMUNICATION",
                    String.format(Locale.US,
                            "%s sent %s while the screen was off, across %d connection(s)",
                            app, fmt(totalBackgroundBytes), flowsWithBackground),
                    2));
        }
    }

    private static void checkDnsReputation(String app, List<PacketLog.Flow> flows, List<Finding> out, DetectionConfig cfg) {
        Set<String> distinctDomains = new HashSet<>();
        String dgaExample = null;

        for (PacketLog.Flow f : flows) {
            if (f.proto == 17 && f.dstPort == 53 && f.dnsQueryName != null) {
                distinctDomains.add(f.dnsQueryName);
                if (dgaExample == null
                        && DnsReputationAnalyzer.looksLikeDga(f.dnsQueryName, cfg.dnsEntropyThreshold, cfg.dnsMinLabelLength)) {
                    dgaExample = f.dnsQueryName;
                }
            }
        }

        if (dgaExample != null) {
            out.add(new Finding(app, "DGA_LIKE_DOMAIN",
                    String.format(Locale.US, "%s queried a high-entropy domain name: %s", app, dgaExample),
                    3));
        }

        if (distinctDomains.size() >= cfg.dnsExcessiveQueryThreshold) {
            out.add(new Finding(app, "EXCESSIVE_DNS_QUERIES",
                    String.format(Locale.US, "%s resolved %d distinct domains this session",
                            app, distinctDomains.size()),
                    1));
        }
    }

    private static void checkMediaTransferCombination(String app, List<PacketLog.Flow> flows,
                                                      List<Finding> perAppFindingsSoFar) {
        if (perAppFindingsSoFar.isEmpty()) return;

        for (PacketLog.Flow f : flows) {
            Level1TrafficAnalyzer.analyze(f);
            if (f.possibleFileTransfer) {
                perAppFindingsSoFar.add(new Finding(app, "SUSPICIOUS_MEDIA_PATTERN",
                        String.format(Locale.US,
                                "%s had a %s transfer to %s:%d alongside other flagged behavior",
                                app, f.trafficPattern, f.dstIp, f.dstPort),
                        2));
                break;
            }
        }
    }

    private static String fmt(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return String.format(Locale.US, "%.1f KB", b / 1024.0);
        return String.format(Locale.US, "%.2f MB", b / (1024.0 * 1024.0));
    }
}