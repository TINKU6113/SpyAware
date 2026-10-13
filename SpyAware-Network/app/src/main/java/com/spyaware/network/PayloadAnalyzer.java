package com.spyaware.network;

import java.util.HashSet;
import java.util.Set;

/**
 * Stage 10, Level 2 (+ SNI + DNS): magic-byte file-signature detection,
 * plaintext TLS SNI extraction, and plaintext DNS query-name extraction.
 * None of these decrypt anything.
 */
public class PayloadAnalyzer {

    private static final Set<Integer> ENCRYPTED_PORTS = new HashSet<>();
    static {
        ENCRYPTED_PORTS.add(443);
        ENCRYPTED_PORTS.add(8443);
        ENCRYPTED_PORTS.add(993);
        ENCRYPTED_PORTS.add(995);
        ENCRYPTED_PORTS.add(465);
    }

    private static final int MAX_ATTEMPTS_PER_FLOW = 4;

    public static synchronized void onNativePayload(String srcIp, int srcPort,
                                                    String dstIp, int dstPort,
                                                    int proto, byte[] payload, boolean outbound) {
        if (payload == null || payload.length == 0) return;

        PacketLog.Flow flow = PacketLog.getFlowByKey(proto, srcIp, srcPort, dstIp, dstPort);
        if (flow == null) return;

        if (flow.detectedFile != null) return;
        if (flow.payloadAttempts >= MAX_ATTEMPTS_PER_FLOW) return;
        flow.payloadAttempts++;

        if (ENCRYPTED_PORTS.contains(dstPort)) {
            flow.payloadAnalysisStatus = "ENCRYPTED_TRAFFIC";
            flow.detectedFile = new DetectedFile(
                    flow.appName, "F" + flow.id, outbound ? "OUTGOING" : "INCOMING",
                    "Not Available", "N/A", flow.totalBytes(), System.currentTimeMillis());
            return;
        }

        String match = matchSignature(payload);
        if (match != null) {
            flow.payloadAnalysisStatus = "ANALYZED";
            flow.detectedFile = new DetectedFile(
                    flow.appName, "F" + flow.id, outbound ? "OUTGOING" : "INCOMING",
                    match, "HIGH", flow.totalBytes(), System.currentTimeMillis());
            return;
        }

        if (flow.payloadAttempts >= MAX_ATTEMPTS_PER_FLOW) {
            flow.payloadAnalysisStatus = "PAYLOAD_NOT_AVAILABLE";
            flow.detectedFile = new DetectedFile(
                    flow.appName, "F" + flow.id, outbound ? "OUTGOING" : "INCOMING",
                    "Not Detected", "N/A", flow.totalBytes(), System.currentTimeMillis());
        }
    }

    public static synchronized void onNativeTlsClientHello(String srcIp, int srcPort,
                                                           String dstIp, int dstPort,
                                                           int proto, byte[] data, boolean outbound) {
        if (!outbound || data == null) return;

        PacketLog.Flow flow = PacketLog.getFlowByKey(proto, srcIp, srcPort, dstIp, dstPort);
        if (flow == null) return;

        String host = TlsSniParser.parseServerName(data);
        if (host != null) {
            flow.sniHostname = host;
        }
    }

    /** New: called for the outbound UDP:53 query packet; extracts the queried hostname. */
    public static synchronized void onNativeDnsQuery(String srcIp, int srcPort,
                                                     String dstIp, int dstPort,
                                                     int proto, byte[] data, boolean outbound) {
        if (!outbound || data == null) return;

        PacketLog.Flow flow = PacketLog.getFlowByKey(proto, srcIp, srcPort, dstIp, dstPort);
        if (flow == null) return;
        if (flow.dnsQueryName != null) return;

        String name = DnsQueryParser.parseQueryName(data);
        if (name != null) {
            flow.dnsQueryName = name;
        }
    }

    private static String matchSignature(byte[] b) {
        if (startsWith(b, 0xFF, 0xD8, 0xFF)) return "JPEG";
        if (startsWith(b, 0x89, 0x50, 0x4E, 0x47)) return "PNG";
        if (startsWith(b, 0x25, 0x50, 0x44, 0x46)) return "PDF";
        if (startsWith(b, 0x50, 0x4B, 0x03, 0x04)) return "ZIP";
        if (b.length >= 8 && b[4] == 'f' && b[5] == 't' && b[6] == 'y' && b[7] == 'p') return "MP4";
        return null;
    }

    private static boolean startsWith(byte[] b, int... expected) {
        if (b.length < expected.length) return false;
        for (int i = 0; i < expected.length; i++) {
            if ((b[i] & 0xFF) != expected[i]) return false;
        }
        return true;
    }
}