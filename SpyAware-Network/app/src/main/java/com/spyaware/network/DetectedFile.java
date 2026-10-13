package com.spyaware.network;

/** Stage 10, Level 2: result of a magic-byte check on a flow's payload. */
public class DetectedFile {
    public final String application;
    public final String flowId;
    public final String direction;   // "OUTGOING" or "INCOMING"
    public final String fileType;    // e.g. "JPEG", "Not Detected", "Not Available"
    public final String confidence;  // "HIGH", "N/A"
    public final long size;          // bytes observed in this flow so far (not necessarily the whole file)
    public final long timestamp;

    public DetectedFile(String application, String flowId, String direction,
                        String fileType, String confidence, long size, long timestamp) {
        this.application = application;
        this.flowId = flowId;
        this.direction = direction;
        this.fileType = fileType;
        this.confidence = confidence;
        this.size = size;
        this.timestamp = timestamp;
    }
}