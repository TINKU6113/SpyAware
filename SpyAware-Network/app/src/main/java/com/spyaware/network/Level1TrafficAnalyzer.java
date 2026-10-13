package com.spyaware.network;

/**
 * Stage 10, Level 1: behavioral indicators derived from metadata we already
 * have (sizes, direction, duration) — never a claim about actual file type.
 */
public class Level1TrafficAnalyzer {

    private static final long LARGE_TRANSFER_BYTES = 500_000;   // 500 KB in one direction
    private static final long SMALL_PACKET_AVG_BYTES = 150;
    private static final long MIN_DURATION_FOR_PATTERN_MS = 2000;

    public static void analyze(PacketLog.Flow flow) {
        long duration = Math.max(flow.durationMs(), 1);
        long avgPacketSize = flow.packets > 0 ? (flow.bytesOut + flow.bytesIn) / flow.packets : 0;

        boolean largeOut = flow.bytesOut >= LARGE_TRANSFER_BYTES;
        boolean largeIn = flow.bytesIn >= LARGE_TRANSFER_BYTES;

        String pattern;
        boolean mediaIndicator = false;
        boolean possibleTransfer = false;
        String direction;

        if (largeOut && !largeIn) {
            pattern = "LARGE_CONTINUOUS_OUTBOUND";
            mediaIndicator = true;
            possibleTransfer = true;
            direction = "OUTGOING";
        } else if (largeIn && !largeOut) {
            pattern = "LARGE_CONTINUOUS_INBOUND";
            mediaIndicator = true;
            possibleTransfer = true;
            direction = "INCOMING";
        } else if (largeOut && largeIn) {
            pattern = "LARGE_BIDIRECTIONAL";
            mediaIndicator = true;
            possibleTransfer = true;
            direction = "BIDIRECTIONAL";
        } else if (avgPacketSize > 0 && avgPacketSize < SMALL_PACKET_AVG_BYTES
                && duration > MIN_DURATION_FOR_PATTERN_MS && flow.packets >= 3) {
            pattern = "SMALL_PERIODIC";
            direction = flow.bytesOut >= flow.bytesIn ? "OUTGOING" : "INCOMING";
        } else {
            pattern = "STEADY";
            direction = flow.bytesOut >= flow.bytesIn ? "OUTGOING" : "INCOMING";
        }

        flow.trafficPattern = pattern;
        flow.mediaTransferIndicator = mediaIndicator;
        flow.possibleFileTransfer = possibleTransfer;
        flow.transferDirection = direction;

        // Level 2 (PayloadAnalyzer) owns this once it has looked at the flow.
        if (flow.payloadAnalysisStatus == null) {
            flow.payloadAnalysisStatus = "PENDING";
        }
    }
}