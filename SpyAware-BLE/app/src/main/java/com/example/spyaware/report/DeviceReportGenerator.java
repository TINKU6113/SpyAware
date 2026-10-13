package com.example.spyaware.report;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.pdf.PdfDocument;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.example.spyaware.security.RiskEngine;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Generates a professional, multi-page vector-and-image PDF investigation
 * report using native Android PdfDocument.
 */
public class DeviceReportGenerator {

    private static final String TAG = "DeviceReportGenerator";
    private static final int PAGE_WIDTH = 595;  // Standard A4 width in points
    private static final int PAGE_HEIGHT = 842; // Standard A4 height in points
    private static final int MARGIN = 36;       // 0.5 inch margin

    public interface ReportGenerationCallback {
        void onSuccess(File pdfFile, DeviceReportData reportData);
        void onError(Exception error);
    }

    private static final ExecutorService executor = Executors.newSingleThreadExecutor();

    private DeviceReportGenerator() {
        // Utility class
    }

    /**
     * Generate report asynchronously on background thread.
     */
    public static void generateReportAsync(
            Context context,
            DeviceReportData reportData,
            ReportGenerationCallback callback
    ) {
        Handler mainHandler = new Handler(Looper.getMainLooper());
        executor.execute(() -> {
            try {
                File pdfFile = generatePdf(context, reportData);
                mainHandler.post(() -> {
                    if (callback != null) {
                        callback.onSuccess(pdfFile, reportData);
                    }
                });
            } catch (Exception e) {
                Log.e(TAG, "Failed to generate report PDF: " + e.getMessage(), e);
                mainHandler.post(() -> {
                    if (callback != null) {
                        callback.onError(e);
                    }
                });
            }
        });
    }

    /**
     * Synchronously generates the multi-page PDF document and writes it to file.
     */
    public static File generatePdf(Context context, DeviceReportData data) throws IOException {
        PdfDocument document = new PdfDocument();

        try {
            // Page 1: Overview, Executive Summary, Score Breakdown, Device Identity
            PdfDocument.PageInfo pageInfo1 = new PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 1).create();
            PdfDocument.Page page1 = document.startPage(pageInfo1);
            drawPage1(page1.getCanvas(), data);
            document.finishPage(page1);

            // Page 2: Signal Intelligence, RSSI Graph, Distance Graph, Timeline, Signal Table
            PdfDocument.PageInfo pageInfo2 = new PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 2).create();
            PdfDocument.Page page2 = document.startPage(pageInfo2);
            drawPage2(page2.getCanvas(), data);
            document.finishPage(page2);

            // Page 3: Geospatial Movement, Map Snapshot, Location Disclosure, Facts vs Inferences, Next Steps
            PdfDocument.PageInfo pageInfo3 = new PdfDocument.PageInfo.Builder(PAGE_WIDTH, PAGE_HEIGHT, 3).create();
            PdfDocument.Page page3 = document.startPage(pageInfo3);
            drawPage3(page3.getCanvas(), data);
            document.finishPage(page3);

            // Output destination
            File reportsDir = new File(context.getCacheDir(), "reports");
            if (!reportsDir.exists()) {
                reportsDir.mkdirs();
            }

            String safeId = data.getDeviceIdentifier().replaceAll("[^a-zA-Z0-9_-]", "_");
            String fileName = "SpyAware_Report_" + safeId + "_" + data.getReportId() + ".pdf";
            File outputFile = new File(reportsDir, fileName);

            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                document.writeTo(fos);
            }

            return outputFile;
        } finally {
            document.close();
        }
    }

    // =========================================================================
    // PAGE 1: EXECUTIVE SUMMARY, SCORE BREAKDOWN, SPECIFICATIONS
    // =========================================================================
    private static void drawPage1(Canvas canvas, DeviceReportData data) {
        float left = MARGIN;
        float right = PAGE_WIDTH - MARGIN;
        float top = MARGIN;
        float currentY = top;

        // Top Accent Banner
        Paint bannerPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        bannerPaint.setColor(Color.rgb(15, 23, 42)); // Deep Slate Navy
        canvas.drawRect(left, currentY, right, currentY + 45f, bannerPaint);

        Paint bannerText = new Paint(Paint.ANTI_ALIAS_FLAG);
        bannerText.setColor(Color.WHITE);
        bannerText.setTextSize(13f);
        bannerText.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText("SPYAWARE BLE SURVEILLANCE DETECTION SYSTEM", left + 12f, currentY + 20f, bannerText);

        Paint subBannerText = new Paint(Paint.ANTI_ALIAS_FLAG);
        subBannerText.setColor(Color.rgb(148, 163, 184));
        subBannerText.setTextSize(9f);
        canvas.drawText("Tactical Signals Intelligence & BLE Surveillance Investigation Report", left + 12f, currentY + 36f, subBannerText);

        // Risk Level Badge
        int riskColor = getRiskColor(data.getRiskLevel());
        Paint badgeBg = new Paint(Paint.ANTI_ALIAS_FLAG);
        badgeBg.setColor(riskColor);
        RectF badgeRect = new RectF(right - 140f, currentY + 8f, right - 10f, currentY + 37f);
        canvas.drawRoundRect(badgeRect, 6f, 6f, badgeBg);

        Paint badgeText = new Paint(Paint.ANTI_ALIAS_FLAG);
        badgeText.setColor(Color.WHITE);
        badgeText.setTextSize(10f);
        badgeText.setTextAlign(Paint.Align.CENTER);
        badgeText.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText(data.getRiskLevel() + " RISK • " + data.getRiskScore() + "/100", badgeRect.centerX(), badgeRect.centerY() + 3.5f, badgeText);

        currentY += 55f;

        // Metadata Grid Box
        Paint metaBg = new Paint(Paint.ANTI_ALIAS_FLAG);
        metaBg.setColor(Color.rgb(241, 245, 249));
        canvas.drawRoundRect(new RectF(left, currentY, right, currentY + 50f), 6f, 6f, metaBg);

        Paint metaBorder = new Paint(Paint.ANTI_ALIAS_FLAG);
        metaBorder.setColor(Color.rgb(203, 213, 225));
        metaBorder.setStyle(Paint.Style.STROKE);
        metaBorder.setStrokeWidth(1f);
        canvas.drawRoundRect(new RectF(left, currentY, right, currentY + 50f), 6f, 6f, metaBorder);

        Paint labelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        labelPaint.setColor(Color.rgb(100, 116, 139));
        labelPaint.setTextSize(8.5f);

        Paint valPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        valPaint.setColor(Color.rgb(15, 23, 42));
        valPaint.setTextSize(9.5f);
        valPaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        float col1 = left + 12f;
        float col2 = left + 140f;
        float col3 = left + 270f;
        float col4 = left + 400f;

        canvas.drawText("REPORT ID:", col1, currentY + 16f, labelPaint);
        canvas.drawText(data.getReportId(), col1, currentY + 32f, valPaint);

        canvas.drawText("GENERATED:", col2, currentY + 16f, labelPaint);
        canvas.drawText(data.getGenerationTimestampFormatted(), col2, currentY + 32f, valPaint);

        canvas.drawText("DEVICE CLASSIFICATION:", col3, currentY + 16f, labelPaint);
        canvas.drawText(data.getClassification(), col3, currentY + 32f, valPaint);

        canvas.drawText("REPORT VERSION:", col4, currentY + 16f, labelPaint);
        canvas.drawText("v" + data.getReportVersion(), col4, currentY + 32f, valPaint);

        currentY += 62f;

        // Section: Behavioural Analysis & Risk Calculation
        currentY = drawSectionHeader(canvas, "1. BEHAVIOURAL ATTENTION & RISK SCORE BREAKDOWN", left, currentY);

        Paint tableBorder = new Paint(Paint.ANTI_ALIAS_FLAG);
        tableBorder.setColor(Color.rgb(226, 232, 240));
        tableBorder.setStyle(Paint.Style.STROKE);
        tableBorder.setStrokeWidth(1f);

        Paint rowHeaderBg = new Paint(Paint.ANTI_ALIAS_FLAG);
        rowHeaderBg.setColor(Color.rgb(241, 245, 249));

        float tableW = right - left;
        canvas.drawRect(left, currentY, right, currentY + 18f, rowHeaderBg);
        canvas.drawRect(left, currentY, right, currentY + 18f, tableBorder);

        Paint thPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        thPaint.setColor(Color.rgb(71, 85, 105));
        thPaint.setTextSize(9f);
        thPaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        canvas.drawText("EVALUATION FACTOR / METRIC", left + 10f, currentY + 12f, thPaint);
        canvas.drawText("ALGORITHMIC CONTRIBUTION", right - 160f, currentY + 12f, thPaint);
        currentY += 18f;

        Map<String, Integer> scoreMap = data.scoreComponents();
        for (Map.Entry<String, Integer> entry : scoreMap.entrySet()) {
            canvas.drawRect(left, currentY, right, currentY + 16f, tableBorder);

            Paint cellText = new Paint(Paint.ANTI_ALIAS_FLAG);
            cellText.setColor(Color.rgb(30, 41, 59));
            cellText.setTextSize(8.5f);
            canvas.drawText(entry.getKey(), left + 10f, currentY + 11.5f, cellText);

            int pts = entry.getValue();
            String ptsText = (pts >= 0 ? "+" : "") + pts + " pts";
            Paint ptsPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
            ptsPaint.setColor(pts >= 0 ? Color.rgb(220, 38, 38) : Color.rgb(22, 163, 74));
            ptsPaint.setTextSize(9f);
            ptsPaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            canvas.drawText(ptsText, right - 160f, currentY + 11.5f, ptsPaint);

            currentY += 16f;
        }

        // Total score row
        canvas.drawRect(left, currentY, right, currentY + 18f, rowHeaderBg);
        canvas.drawRect(left, currentY, right, currentY + 18f, tableBorder);
        canvas.drawText("TOTAL COMPUTED RISK SCORE", left + 10f, currentY + 12f, thPaint);

        Paint totalPtsPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        totalPtsPaint.setColor(riskColor);
        totalPtsPaint.setTextSize(10f);
        totalPtsPaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText(data.getRiskScore() + " / 100 (" + data.getRiskLevel() + ")", right - 160f, currentY + 13f, totalPtsPaint);
        currentY += 28f;

        // Specific Flagged Evidence Callout
        Paint calloutBg = new Paint(Paint.ANTI_ALIAS_FLAG);
        calloutBg.setColor(Color.rgb(254, 242, 242)); // Light red tint
        Paint calloutBorder = new Paint(Paint.ANTI_ALIAS_FLAG);
        calloutBorder.setColor(Color.rgb(252, 165, 165));
        calloutBorder.setStyle(Paint.Style.STROKE);
        calloutBorder.setStrokeWidth(1f);

        float calloutHeight = 18f + (data.getFlaggedEvidence().size() * 14f);
        canvas.drawRoundRect(new RectF(left, currentY, right, currentY + calloutHeight), 6f, 6f, calloutBg);
        canvas.drawRoundRect(new RectF(left, currentY, right, currentY + calloutHeight), 6f, 6f, calloutBorder);

        Paint calloutTitle = new Paint(Paint.ANTI_ALIAS_FLAG);
        calloutTitle.setColor(Color.rgb(185, 28, 28));
        calloutTitle.setTextSize(9.5f);
        calloutTitle.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText("FLAGGED SURVEILLANCE RISK EVIDENCE:", left + 10f, currentY + 13f, calloutTitle);

        float evY = currentY + 26f;
        Paint evPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        evPaint.setColor(Color.rgb(69, 10, 10));
        evPaint.setTextSize(8.5f);

        for (String ev : data.getFlaggedEvidence()) {
            canvas.drawText("• " + ev, left + 12f, evY, evPaint);
            evY += 13.5f;
        }
        currentY += calloutHeight + 14f;

        // Section: Target Device Identity Specifications
        currentY = drawSectionHeader(canvas, "2. DEVICE IDENTITY & BLE SPECIFICATIONS", left, currentY);

        currentY = drawKeyValueTable(canvas, left, right, currentY, new String[][]{
                {"Device Advertised Name", data.getDeviceName()},
                {"Physical MAC Address", data.getMacAddress()},
                {"Manufacturer Information", data.getResolvedManufacturer()},
                {"Raw Manufacturer Data", data.getManufacturerInfo()},
                {"Service UUIDs", data.getServiceUuids()},
                {"Transmit Power (TX)", data.getTxPower() != Integer.MIN_VALUE ? data.getTxPower() + " dBm" : "Not Advertised"},
                {"BLE SHA-256 Fingerprint", data.getBleFingerprint()},
                {"Identity Confidence Note", data.getIdentityConfidence()}
        });

        currentY += 14f;

        // Section: Observation Window & Presence Tracking
        currentY = drawSectionHeader(canvas, "3. OBSERVATION WINDOW & PRESENCE TIMELINE", left, currentY);

        currentY = drawKeyValueTable(canvas, left, right, currentY, new String[][]{
                {"First Observed Timestamp", data.getFirstObservedFormatted()},
                {"Last Observed Timestamp", data.getLastObservedFormatted()},
                {"Total Elapsed Window", data.getElapsedWindowFormatted()},
                {"Active Observation Duration", data.getActivePresenceDurationFormatted() + " (excluding gaps)"},
                {"Total Packets Received", String.valueOf(data.getPacketCount())},
                {"Discrete Presence Sessions", String.valueOf(data.getSessionCount())},
                {"Live Presence Status", data.isCurrentlyPresent() ? "CURRENTLY BROADCASTING / PRESENT" : "ABSENT / SILENT"},
                {"Persistence Category", data.getPersistenceState()},
                {"Average Advertising Interval", String.format(Locale.US, "%.0f ms", data.getAverageIntervalMs())},
                {"Longest Unobserved Gap", data.getLongestGapFormatted() + " (" + data.getObservationGapsCount() + " gap periods total)"}
        });

        drawPageFooter(canvas, 1, 3);
    }

    // =========================================================================
    // PAGE 2: SIGNAL INTELLIGENCE & GRAPHS
    // =========================================================================
    private static void drawPage2(Canvas canvas, DeviceReportData data) {
        float left = MARGIN;
        float right = PAGE_WIDTH - MARGIN;
        float currentY = MARGIN;

        currentY = drawSubPageHeader(canvas, "4. BLE SIGNAL INTELLIGENCE & TEMPORAL ANALYSIS", left, right, currentY);

        int graphWidth = (int) (right - left);
        int graphHeight = 175;

        // Graph 1: RSSI vs Time
        Paint sectionLabel = new Paint(Paint.ANTI_ALIAS_FLAG);
        sectionLabel.setColor(Color.rgb(15, 23, 42));
        sectionLabel.setTextSize(10f);
        sectionLabel.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        canvas.drawText("A. Received Signal Strength (RSSI) History Across Time", left, currentY + 12f, sectionLabel);
        currentY += 16f;

        Bitmap rssiGraph = ReportGraphRenderer.renderRssiGraph(data, graphWidth, graphHeight);
        canvas.drawBitmap(rssiGraph, left, currentY, null);
        currentY += graphHeight + 14f;

        // Graph 2: Distance vs Time
        canvas.drawText("B. Estimated Target Distance (m) Over Time [Log-Distance Path Loss]", left, currentY + 12f, sectionLabel);
        currentY += 16f;

        Bitmap distGraph = ReportGraphRenderer.renderDistanceGraph(data, graphWidth, graphHeight);
        canvas.drawBitmap(distGraph, left, currentY, null);
        currentY += graphHeight + 14f;

        // Graph 3: Timeline of Sessions
        canvas.drawText("C. Observation Timeline: Active Sessions vs Unobserved Radio Silences", left, currentY + 12f, sectionLabel);
        currentY += 16f;

        int timelineHeight = 90;
        Bitmap timelineGraph = ReportGraphRenderer.renderTimelineGraph(data, graphWidth, timelineHeight);
        canvas.drawBitmap(timelineGraph, left, currentY, null);
        currentY += timelineHeight + 16f;

        // Signal Statistics Table
        currentY = drawSectionHeader(canvas, "SIGNAL METRICS & DISTANCE MODEL PARAMETERS", left, currentY);

        currentY = drawKeyValueTable(canvas, left, right, currentY, new String[][]{
                {"Latest RSSI", data.getLatestRssi() + " dBm"},
                {"Smoothed Average RSSI", String.format(Locale.US, "%.1f dBm", data.getAverageRssi())},
                {"Observed RSSI Range", data.getMinRssi() + " dBm to " + data.getMaxRssi() + " dBm"},
                {"Signal Trend (Approach Detection)", data.getRssiTrend()},
                {"Current Estimated Distance", data.getCurrentEstimatedDistance() >= 0 ? String.format(Locale.US, "%.2f m", data.getCurrentEstimatedDistance()) : "Unavailable"},
                {"Estimated Distance Range", String.format(Locale.US, "Min: %.2f m | Max: %.2f m | Avg: %.2f m", data.getMinEstimatedDistance(), data.getMaxEstimatedDistance(), data.getAvgEstimatedDistance())},
                {"Distance Estimation Method", data.getDistanceEstimationMethod() + " (" + (data.isCalibrated() ? "Calibrated at 1m" : "Default -59 dBm Reference") + ")"},
                {"Distance Model Confidence", data.getDistanceConfidence()},
                {"Proximity State Classification", data.getProximityState()}
        });

        drawPageFooter(canvas, 2, 3);
    }

    // =========================================================================
    // PAGE 3: GEOSPATIAL ANALYSIS, DISCLOSURE, NEXT STEPS
    // =========================================================================
    private static void drawPage3(Canvas canvas, DeviceReportData data) {
        float left = MARGIN;
        float right = PAGE_WIDTH - MARGIN;
        float currentY = MARGIN;

        currentY = drawSubPageHeader(canvas, "5. GEOSPATIAL & FORENSIC MOVEMENT ANALYSIS", left, right, currentY);

        int mapWidth = (int) (right - left);
        int mapHeight = 220;

        Bitmap mapBitmap = data.getMapSnapshotBitmap();
        boolean hasSnapshot = (mapBitmap != null);

        if (hasSnapshot) {
            // Draw real captured Google Maps snapshot
            Rect srcRect = new Rect(0, 0, mapBitmap.getWidth(), mapBitmap.getHeight());
            RectF dstRect = new RectF(left, currentY, right, currentY + mapHeight);
            canvas.drawBitmap(mapBitmap, srcRect, dstRect, null);

            // Border
            Paint border = new Paint(Paint.ANTI_ALIAS_FLAG);
            border.setColor(Color.rgb(15, 23, 42));
            border.setStyle(Paint.Style.STROKE);
            border.setStrokeWidth(2f);
            canvas.drawRect(dstRect, border);

            currentY += mapHeight + 10f;
        } else if (!data.getTargetLocationPoints().isEmpty() || !data.getUserLocationPoints().isEmpty()) {
            // Draw schematic GPS track
            Bitmap schematic = ReportGraphRenderer.renderSchematicGpsTrack(data, mapWidth, mapHeight);
            canvas.drawBitmap(schematic, left, currentY, null);
            currentY += mapHeight + 10f;
        } else {
            // Informative fallback box
            Paint boxBg = new Paint(Paint.ANTI_ALIAS_FLAG);
            boxBg.setColor(Color.rgb(241, 245, 249));
            canvas.drawRoundRect(new RectF(left, currentY, right, currentY + 70f), 6f, 6f, boxBg);

            Paint boxText = new Paint(Paint.ANTI_ALIAS_FLAG);
            boxText.setColor(Color.rgb(71, 85, 105));
            boxText.setTextSize(10f);
            boxText.setTextAlign(Paint.Align.CENTER);
            canvas.drawText("Geospatial Map Snapshot Unavailable", left + (mapWidth / 2f), currentY + 32f, boxText);

            Paint boxSub = new Paint(Paint.ANTI_ALIAS_FLAG);
            boxSub.setColor(Color.rgb(148, 163, 184));
            boxSub.setTextSize(8.5f);
            boxSub.setTextAlign(Paint.Align.CENTER);
            canvas.drawText("No GPS location points were recorded or Google Maps view was not loaded at time of report generation.", left + (mapWidth / 2f), currentY + 48f, boxSub);

            currentY += 80f;
        }

        // Location Semantics Disclosure Box
        Paint discBg = new Paint(Paint.ANTI_ALIAS_FLAG);
        discBg.setColor(Color.rgb(254, 249, 195)); // Light yellow alert
        Paint discBorder = new Paint(Paint.ANTI_ALIAS_FLAG);
        discBorder.setColor(Color.rgb(234, 179, 8));
        discBorder.setStyle(Paint.Style.STROKE);
        discBorder.setStrokeWidth(1f);

        canvas.drawRoundRect(new RectF(left, currentY, right, currentY + 48f), 6f, 6f, discBg);
        canvas.drawRoundRect(new RectF(left, currentY, right, currentY + 48f), 6f, 6f, discBorder);

        Paint discTitle = new Paint(Paint.ANTI_ALIAS_FLAG);
        discTitle.setColor(Color.rgb(133, 77, 14));
        discTitle.setTextSize(8.5f);
        discTitle.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText("CRITICAL LOCATION SEMANTICS & SENSOR BOUNDARY NOTICE:", left + 10f, currentY + 14f, discTitle);

        Paint discText = new Paint(Paint.ANTI_ALIAS_FLAG);
        discText.setColor(Color.rgb(113, 63, 18));
        discText.setTextSize(7.5f);
        canvas.drawText("• Recorded GPS track represents smartphone (investigator) position, NOT the remote BLE emitter's onboard GPS.", left + 10f, currentY + 26f, discText);
        canvas.drawText("• BLE signals are omnidirectional. Bearing cannot be resolved by a single smartphone receiver.", left + 10f, currentY + 36f, discText);
        canvas.drawText("• Range boundary is mathematically estimated from signal loss and indicates proximity zone, not guaranteed physical boundary.", left + 10f, currentY + 44f, discText);

        currentY += 56f;

        // Section: Measured Facts vs Algorithmic Inferences
        currentY = drawSectionHeader(canvas, "6. MEASURED FACTS VERSUS ALGORITHMIC INFERENCES", left, currentY);

        Paint thBg = new Paint(Paint.ANTI_ALIAS_FLAG);
        thBg.setColor(Color.rgb(241, 245, 249));
        Paint thBorder = new Paint(Paint.ANTI_ALIAS_FLAG);
        thBorder.setColor(Color.rgb(203, 213, 225));
        thBorder.setStyle(Paint.Style.STROKE);
        thBorder.setStrokeWidth(1f);

        canvas.drawRect(left, currentY, right, currentY + 18f, thBg);
        canvas.drawRect(left, currentY, right, currentY + 18f, thBorder);

        Paint thP = new Paint(Paint.ANTI_ALIAS_FLAG);
        thP.setColor(Color.rgb(15, 23, 42));
        thP.setTextSize(8.5f);
        thP.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        float midX = left + ((right - left) / 2f);
        canvas.drawText("MEASURED PHYSICAL FACTS (Empirical)", left + 10f, currentY + 12f, thP);
        canvas.drawText("ALGORITHMIC INFERENCES (Derived)", midX + 10f, currentY + 12f, thP);
        currentY += 18f;

        for (DeviceReportData.FactInferencePair pair : data.getFactsVsInferences()) {
            float rowH = 24f;
            canvas.drawRect(left, currentY, right, currentY + rowH, thBorder);
            canvas.drawLine(midX, currentY, midX, currentY + rowH, thBorder);

            Paint cellText = new Paint(Paint.ANTI_ALIAS_FLAG);
            cellText.setColor(Color.rgb(30, 41, 59));
            cellText.setTextSize(7.5f);

            canvas.drawText(pair.getMeasuredFact(), left + 8f, currentY + 15f, cellText);
            canvas.drawText(pair.getAlgorithmicInference(), midX + 8f, currentY + 15f, cellText);

            currentY += rowH;
        }

        currentY += 14f;

        // Section: Recommended Next Steps
        currentY = drawSectionHeader(canvas, "7. SUGGESTED NEXT STEPS & COUNTERMEASURES", left, currentY);

        Paint recPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        recPaint.setColor(Color.rgb(30, 41, 59));
        recPaint.setTextSize(8.5f);

        for (String step : data.getRecommendedNextSteps()) {
            canvas.drawText("• " + step, left + 8f, currentY + 11f, recPaint);
            currentY += 14f;
        }

        currentY += 14f;

        // Sign-off / Verification Box
        Paint signBg = new Paint(Paint.ANTI_ALIAS_FLAG);
        signBg.setColor(Color.rgb(248, 250, 252));
        canvas.drawRoundRect(new RectF(left, currentY, right, currentY + 45f), 6f, 6f, signBg);
        canvas.drawRoundRect(new RectF(left, currentY, right, currentY + 45f), 6f, 6f, thBorder);

        Paint signText = new Paint(Paint.ANTI_ALIAS_FLAG);
        signText.setColor(Color.rgb(71, 85, 105));
        signText.setTextSize(8f);
        canvas.drawText("FORENSIC RECORD INTEGRITY: Generated strictly on-device by SpyAware. No remote cloud transmission occurred.", left + 10f, currentY + 16f, signText);
        canvas.drawText("Target Device Identifier: " + data.getDeviceIdentifier() + " | Signature SHA-256 Fingerprint Verified.", left + 10f, currentY + 30f, signText);

        drawPageFooter(canvas, 3, 3);
    }

    // =========================================================================
    // HELPER DRAWING METHODS
    // =========================================================================
    private static float drawSectionHeader(Canvas canvas, String title, float left, float currentY) {
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        p.setColor(Color.rgb(15, 23, 42));
        p.setTextSize(10.5f);
        p.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        canvas.drawText(title, left, currentY + 12f, p);

        Paint line = new Paint(Paint.ANTI_ALIAS_FLAG);
        line.setColor(Color.rgb(15, 23, 42));
        line.setStrokeWidth(1.5f);
        canvas.drawLine(left, currentY + 16f, left + 180f, currentY + 16f, line);

        return currentY + 24f;
    }

    private static float drawSubPageHeader(Canvas canvas, String title, float left, float right, float currentY) {
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        p.setColor(Color.rgb(15, 23, 42));
        p.setTextSize(11f);
        p.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText(title, left, currentY + 15f, p);

        Paint line = new Paint(Paint.ANTI_ALIAS_FLAG);
        line.setColor(Color.rgb(203, 213, 225));
        line.setStrokeWidth(1f);
        canvas.drawLine(left, currentY + 22f, right, currentY + 22f, line);

        return currentY + 30f;
    }

    private static float drawKeyValueTable(Canvas canvas, float left, float right, float currentY, String[][] rows) {
        Paint border = new Paint(Paint.ANTI_ALIAS_FLAG);
        border.setColor(Color.rgb(226, 232, 240));
        border.setStyle(Paint.Style.STROKE);
        border.setStrokeWidth(1f);

        Paint keyPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        keyPaint.setColor(Color.rgb(71, 85, 105));
        keyPaint.setTextSize(8.5f);
        keyPaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));

        Paint valPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        valPaint.setColor(Color.rgb(15, 23, 42));
        valPaint.setTextSize(8.5f);

        float splitX = left + 160f;

        for (String[] row : rows) {
            String key = row[0];
            String val = row[1];

            // Truncate if very long
            if (val != null && val.length() > 65) {
                val = val.substring(0, 62) + "...";
            }

            canvas.drawRect(left, currentY, right, currentY + 15f, border);
            canvas.drawLine(splitX, currentY, splitX, currentY + 15f, border);

            canvas.drawText(key, left + 8f, currentY + 11f, keyPaint);
            canvas.drawText(val != null ? val : "--", splitX + 8f, currentY + 11f, valPaint);

            currentY += 15f;
        }

        return currentY;
    }

    private static void drawPageFooter(Canvas canvas, int pageNum, int totalPages) {
        float bottom = PAGE_HEIGHT - MARGIN + 15f;

        Paint line = new Paint(Paint.ANTI_ALIAS_FLAG);
        line.setColor(Color.rgb(226, 232, 240));
        line.setStrokeWidth(1f);
        canvas.drawLine(MARGIN, bottom - 16f, PAGE_WIDTH - MARGIN, bottom - 16f, line);

        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        p.setColor(Color.rgb(148, 163, 184));
        p.setTextSize(8f);

        canvas.drawText("SpyAware BLE Surveillance Detection System • Confidential Investigation Document", MARGIN, bottom - 4f, p);

        String pageText = "Page " + pageNum + " of " + totalPages;
        p.setTextAlign(Paint.Align.RIGHT);
        canvas.drawText(pageText, PAGE_WIDTH - MARGIN, bottom - 4f, p);
    }

    private static int getRiskColor(String riskLevel) {
        if (RiskEngine.CRITICAL.equalsIgnoreCase(riskLevel)) {
            return Color.rgb(220, 38, 38); // Crimson
        } else if (RiskEngine.HIGH.equalsIgnoreCase(riskLevel)) {
            return Color.rgb(234, 88, 12); // Orange
        } else if (RiskEngine.MEDIUM.equalsIgnoreCase(riskLevel)) {
            return Color.rgb(202, 138, 4);  // Amber
        } else {
            return Color.rgb(22, 163, 74);  // Green
        }
    }
}
