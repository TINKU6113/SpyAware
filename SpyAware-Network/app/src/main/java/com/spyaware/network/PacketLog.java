package com.spyaware.network;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Stage 5 + 6 + 7 + 10 (+ screen-state + SNI + DNS): receives per-packet
 * metadata from native code, reconstructs it into flows, attributes each
 * flow to an app, and carries behavioral/file-analysis/background/hostname/
 * DNS fields per flow.
 */
public class PacketLog {

    private static final int MAX_FLOWS = 500;
    private static final int SHOW_FLOWS = 6;
    private static final long IDLE_NEW_FLOW_MS = 30_000;
    private static final long ACTIVE_MS = 5_000;

    public static class Flow {
        public final int id;
        public final int proto;
        public final String srcIp;
        public final int srcPort;
        public final String dstIp;
        public final int dstPort;
        public final long firstSeen;
        public long lastSeen;
        public long packets;
        public long bytesOut;
        public long bytesIn;
        public String appName;

        // ---- Stage 10 ----
        public String trafficPattern = "PENDING";
        public boolean mediaTransferIndicator = false;
        public boolean possibleFileTransfer = false;
        public String transferDirection = "NONE";
        public String payloadAnalysisStatus = null;
        public DetectedFile detectedFile = null;
        public int payloadAttempts = 0;

        // ---- Screen-state awareness ----
        public long backgroundBytes = 0;
        public long backgroundPackets = 0;
        public boolean hadBackgroundActivity = false;

        // ---- SNI ----
        public String sniHostname = null;

        // ---- DNS (new) ----
        public String dnsQueryName = null; // set once, for UDP:53 flows, from the query packet

        Flow(int id, int proto, String srcIp, int srcPort,
             String dstIp, int dstPort, long now) {
            this.id = id;
            this.proto = proto;
            this.srcIp = srcIp;
            this.srcPort = srcPort;
            this.dstIp = dstIp;
            this.dstPort = dstPort;
            this.firstSeen = now;
            this.lastSeen = now;
            this.appName = AppAttribution.resolve(proto, srcIp, srcPort, dstIp, dstPort);
        }

        public long durationMs() { return lastSeen - firstSeen; }
        public long totalBytes() { return bytesOut + bytesIn; }
    }

    private static long startTime = System.currentTimeMillis();
    private static long totalPackets;
    private static long bytesSent;
    private static long bytesReceived;

    private static final Map<String, Flow> flows = new HashMap<>();
    private static int nextFlowId = 1;
    private static int totalFlowsCreated = 0;

    public static synchronized void reset() {
        startTime = System.currentTimeMillis();
        totalPackets = bytesSent = bytesReceived = 0;
        flows.clear();
        nextFlowId = 1;
        totalFlowsCreated = 0;
    }

    public static synchronized long getTotalPackets() { return totalPackets; }
    public static synchronized long getBytesSent() { return bytesSent; }
    public static synchronized long getBytesReceived() { return bytesReceived; }
    public static synchronized long getStartTime() { return startTime; }

    private static String keyFor(int proto, String srcIp, int srcPort, String dstIp, int dstPort) {
        return proto + "|" + srcIp + ":" + srcPort + "|" + dstIp + ":" + dstPort;
    }

    public static synchronized void onPacket(String srcIp, int srcPort,
                                             String dstIp, int dstPort,
                                             int proto, int len, boolean outbound) {
        long now = System.currentTimeMillis();

        totalPackets++;
        if (outbound) bytesSent += len; else bytesReceived += len;

        String key = keyFor(proto, srcIp, srcPort, dstIp, dstPort);
        Flow flow = flows.get(key);

        if (flow != null && now - flow.lastSeen > IDLE_NEW_FLOW_MS) {
            flows.remove(key);
            flow = null;
        }

        if (flow == null) {
            if (flows.size() >= MAX_FLOWS) evictOldest();
            flow = new Flow(nextFlowId++, proto, srcIp, srcPort, dstIp, dstPort, now);
            flows.put(key, flow);
            totalFlowsCreated++;
        }

        flow.lastSeen = now;
        flow.packets++;
        if (outbound) flow.bytesOut += len; else flow.bytesIn += len;

        if (!ScreenStateMonitor.isScreenOn()) {
            flow.backgroundBytes += len;
            flow.backgroundPackets++;
            flow.hadBackgroundActivity = true;
        }
    }

    public static synchronized Flow getFlowByKey(int proto, String srcIp, int srcPort,
                                                 String dstIp, int dstPort) {
        return flows.get(keyFor(proto, srcIp, srcPort, dstIp, dstPort));
    }

    private static void evictOldest() {
        String oldestKey = null;
        long oldest = Long.MAX_VALUE;
        for (Map.Entry<String, Flow> e : flows.entrySet()) {
            if (e.getValue().lastSeen < oldest) {
                oldest = e.getValue().lastSeen;
                oldestKey = e.getKey();
            }
        }
        if (oldestKey != null) flows.remove(oldestKey);
    }

    public static synchronized List<Flow> getFlows() {
        List<Flow> list = new ArrayList<>(flows.values());
        Collections.sort(list, (a, b) -> Long.compare(b.lastSeen, a.lastSeen));
        return list;
    }

    private static String protoName(int proto) {
        switch (proto) {
            case 6:  return "TCP";
            case 17: return "UDP";
            case 1:  return "ICMP";
            case 58: return "ICMPv6";
            default: return "P" + proto;
        }
    }

    private static String fmtBytes(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return String.format(Locale.US, "%.1f KB", b / 1024.0);
        return String.format(Locale.US, "%.2f MB", b / (1024.0 * 1024.0));
    }

    private static String fmtDuration(long ms) {
        return String.format(Locale.US, "%.1f s", ms / 1000.0);
    }

    public static synchronized String getSummary() {
        long now = System.currentTimeMillis();
        long seconds = (now - startTime) / 1000;

        int active = 0;
        for (Flow f : flows.values()) {
            if (now - f.lastSeen <= ACTIVE_MS) active++;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Packets: ").append(totalPackets)
                .append("   Duration: ").append(seconds).append("s\n");
        sb.append("Sent: ").append(fmtBytes(bytesSent))
                .append("   Received: ").append(fmtBytes(bytesReceived)).append("\n");
        sb.append("Connections: ").append(totalFlowsCreated)
                .append("   Active: ").append(active)
                .append("   Screen: ").append(ScreenStateMonitor.isScreenOn() ? "ON" : "OFF").append("\n\n");
        sb.append("Latest connections:\n");

        List<Flow> sorted = getFlows();
        int shown = 0;
        for (Flow f : sorted) {
            if (shown++ >= SHOW_FLOWS) break;
            boolean isActive = now - f.lastSeen <= ACTIVE_MS;
            String dstLabel = f.sniHostname != null
                    ? f.sniHostname + " (" + f.dstIp + ")"
                    : f.dstIp;

            sb.append("#").append(f.id).append(" ")
                    .append(f.appName).append(" ")
                    .append(protoName(f.proto)).append(" ")
                    .append(dstLabel).append(":").append(f.dstPort)
                    .append(isActive ? "  [ACTIVE]" : "  [closed]").append("\n");
            sb.append("   ").append(fmtDuration(f.durationMs()))
                    .append("  out ").append(fmtBytes(f.bytesOut))
                    .append("  in ").append(fmtBytes(f.bytesIn))
                    .append("  pkts ").append(f.packets);
            if (f.hadBackgroundActivity) {
                sb.append("  [bg: ").append(fmtBytes(f.backgroundBytes)).append("]");
            }
            if (f.dnsQueryName != null) {
                sb.append("  [dns: ").append(f.dnsQueryName).append("]");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    public static synchronized String getPayloadSummary() {
        List<Flow> sorted = getFlows();
        StringBuilder sb = new StringBuilder();
        int shown = 0;
        for (Flow f : sorted) {
            if (shown++ >= SHOW_FLOWS) break;
            Level1TrafficAnalyzer.analyze(f);

            String dstLabel = f.sniHostname != null ? f.sniHostname : f.dstIp;
            sb.append(f.appName).append(" -> ").append(dstLabel).append(":").append(f.dstPort).append("\n");
            sb.append("   Pattern: ").append(f.trafficPattern)
                    .append("   Media: ").append(f.mediaTransferIndicator ? "possible" : "no").append("\n");

            if (f.detectedFile != null) {
                sb.append("   File Type: ").append(f.detectedFile.fileType);
                if ("Not Available".equals(f.detectedFile.fileType)) {
                    sb.append("   Reason: Encrypted payload");
                } else {
                    sb.append("   Confidence: ").append(f.detectedFile.confidence);
                }
                sb.append("\n");
            } else {
                sb.append("   File Type: ").append(f.payloadAnalysisStatus == null ? "PENDING" : f.payloadAnalysisStatus).append("\n");
            }
        }
        return sb.length() == 0 ? "(no flows yet)\n" : sb.toString();
    }
}