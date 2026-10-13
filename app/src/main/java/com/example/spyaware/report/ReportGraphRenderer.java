package com.example.spyaware.report;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;

import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.model.TargetLocationPoint;
import com.example.spyaware.model.UserLocationPoint;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Renders high-resolution, anti-aliased analytical graphs for inclusion in
 * the PDF investigation report.
 */
public class ReportGraphRenderer {

    private static final long OBSERVATION_GAP_THRESHOLD_MS = 15000; // 15 seconds

    private ReportGraphRenderer() {
        // Utility class
    }

    /**
     * Renders RSSI (dBm) versus Timestamp graph.
     */
    public static Bitmap renderRssiGraph(DeviceReportData data, int width, int height) {
        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);

        // Background
        canvas.drawColor(Color.rgb(248, 250, 252)); // Light slate

        List<Integer> rssiList = data.getRssiHistory();
        List<Long> tsList = data.getRssiTimestamps();

        Paint borderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        borderPaint.setColor(Color.rgb(203, 213, 225));
        borderPaint.setStyle(Paint.Style.STROKE);
        borderPaint.setStrokeWidth(2f);
        canvas.drawRect(1, 1, width - 1, height - 1, borderPaint);

        // Check for insufficient data
        if (rssiList == null || rssiList.size() < 2 || tsList == null || tsList.size() != rssiList.size()) {
            renderInsufficientData(canvas, width, height, "RSSI vs Time: Insufficient observation data (<2 packets)");
            return bitmap;
        }

        float paddingLeft = 65f;
        float paddingRight = 30f;
        float paddingTop = 35f;
        float paddingBottom = 45f;

        float plotWidth = width - paddingLeft - paddingRight;
        float plotHeight = height - paddingTop - paddingBottom;

        // Title
        Paint titlePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        titlePaint.setColor(Color.rgb(15, 23, 42));
        titlePaint.setTextSize(14f);
        titlePaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText("RSSI Signal Strength (dBm) vs Observation Time", paddingLeft, 22f, titlePaint);

        // Y-axis range: -100 dBm to -30 dBm
        float minY = -100f;
        float maxY = -30f;

        long minTime = tsList.get(0);
        long maxTime = tsList.get(tsList.size() - 1);
        if (maxTime == minTime) {
            maxTime = minTime + 1000;
        }

        // Draw Y grid lines
        Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        gridPaint.setColor(Color.rgb(226, 232, 240));
        gridPaint.setStrokeWidth(1f);

        Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        textPaint.setColor(Color.rgb(100, 116, 139));
        textPaint.setTextSize(10f);

        int[] ySteps = {-100, -90, -80, -70, -60, -50, -40, -30};
        for (int yVal : ySteps) {
            float yRatio = (yVal - minY) / (maxY - minY);
            float yPos = paddingTop + plotHeight - (yRatio * plotHeight);

            canvas.drawLine(paddingLeft, yPos, width - paddingRight, yPos, gridPaint);
            String label = yVal + " dBm";
            canvas.drawText(label, 8f, yPos + 4f, textPaint);
        }

        // Draw X time ticks (start, middle, end)
        SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
        long[] timeTicks = {minTime, minTime + (maxTime - minTime) / 2, maxTime};
        for (long t : timeTicks) {
            float xRatio = (float) (t - minTime) / (float) (maxTime - minTime);
            float xPos = paddingLeft + (xRatio * plotWidth);

            canvas.drawLine(xPos, paddingTop, xPos, paddingTop + plotHeight, gridPaint);
            String tLabel = timeFmt.format(new Date(t));
            canvas.drawText(tLabel, xPos - 22f, height - 15f, textPaint);
        }

        // Plot line with gap breaking
        Paint linePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        linePaint.setColor(Color.rgb(2, 132, 199)); // Cyan-blue
        linePaint.setStrokeWidth(2.5f);
        linePaint.setStyle(Paint.Style.STROKE);

        Paint dotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        dotPaint.setColor(Color.rgb(3, 105, 161));
        dotPaint.setStyle(Paint.Style.FILL);

        Path currentPath = new Path();
        boolean pathActive = false;

        for (int i = 0; i < rssiList.size(); i++) {
            long curTime = tsList.get(i);
            int curRssi = Math.max(-100, Math.min(-30, rssiList.get(i)));

            float x = paddingLeft + ((float) (curTime - minTime) / (float) (maxTime - minTime)) * plotWidth;
            float y = paddingTop + plotHeight - (((curRssi - minY) / (maxY - minY)) * plotHeight);

            // Check gap from previous
            if (i > 0) {
                long gap = curTime - tsList.get(i - 1);
                if (gap > OBSERVATION_GAP_THRESHOLD_MS) {
                    // Gap detected: finish current path and start new segment to avoid false interpolation
                    if (pathActive) {
                        canvas.drawPath(currentPath, linePaint);
                        currentPath.reset();
                        pathActive = false;
                    }
                }
            }

            if (!pathActive) {
                currentPath.moveTo(x, y);
                pathActive = true;
            } else {
                currentPath.lineTo(x, y);
            }

            canvas.drawCircle(x, y, 2.5f, dotPaint);
        }

        if (pathActive) {
            canvas.drawPath(currentPath, linePaint);
        }

        return bitmap;
    }

    /**
     * Renders Estimated Distance (meters) versus Timestamp graph.
     */
    public static Bitmap renderDistanceGraph(DeviceReportData data, int width, int height) {
        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);

        canvas.drawColor(Color.rgb(248, 250, 252));

        List<Integer> rssiList = data.getRssiHistory();
        List<Long> tsList = data.getRssiTimestamps();

        Paint borderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        borderPaint.setColor(Color.rgb(203, 213, 225));
        borderPaint.setStyle(Paint.Style.STROKE);
        borderPaint.setStrokeWidth(2f);
        canvas.drawRect(1, 1, width - 1, height - 1, borderPaint);

        if (rssiList == null || rssiList.size() < 2 || tsList == null || tsList.size() != rssiList.size()) {
            renderInsufficientData(canvas, width, height, "Distance vs Time: Insufficient observation data (<2 packets)");
            return bitmap;
        }

        float paddingLeft = 65f;
        float paddingRight = 30f;
        float paddingTop = 35f;
        float paddingBottom = 45f;

        float plotWidth = width - paddingLeft - paddingRight;
        float plotHeight = height - paddingTop - paddingBottom;

        Paint titlePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        titlePaint.setColor(Color.rgb(15, 23, 42));
        titlePaint.setTextSize(14f);
        titlePaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText("Estimated Distance (m) vs Observation Time [Log-Distance Path Loss]", paddingLeft, 22f, titlePaint);

        // Compute distances
        double refRssi = data.getReferenceRssiAtOneMeter();
        float maxDist = (float) Math.max(10.0, Math.ceil(data.getMaxEstimatedDistance() * 1.2));
        if (maxDist > 40f) maxDist = 40f;
        float minDist = 0f;

        long minTime = tsList.get(0);
        long maxTime = tsList.get(tsList.size() - 1);
        if (maxTime == minTime) maxTime = minTime + 1000;

        Paint gridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        gridPaint.setColor(Color.rgb(226, 232, 240));
        gridPaint.setStrokeWidth(1f);

        Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        textPaint.setColor(Color.rgb(100, 116, 139));
        textPaint.setTextSize(10f);

        float distStep = maxDist / 5f;
        for (int i = 0; i <= 5; i++) {
            float dVal = i * distStep;
            float yRatio = (dVal - minDist) / (maxDist - minDist);
            float yPos = paddingTop + plotHeight - (yRatio * plotHeight);

            canvas.drawLine(paddingLeft, yPos, width - paddingRight, yPos, gridPaint);
            String label = String.format(Locale.US, "%.1f m", dVal);
            canvas.drawText(label, 12f, yPos + 4f, textPaint);
        }

        SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
        long[] timeTicks = {minTime, minTime + (maxTime - minTime) / 2, maxTime};
        for (long t : timeTicks) {
            float xRatio = (float) (t - minTime) / (float) (maxTime - minTime);
            float xPos = paddingLeft + (xRatio * plotWidth);

            canvas.drawLine(xPos, paddingTop, xPos, paddingTop + plotHeight, gridPaint);
            String tLabel = timeFmt.format(new Date(t));
            canvas.drawText(tLabel, xPos - 22f, height - 15f, textPaint);
        }

        Paint linePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        linePaint.setColor(Color.rgb(234, 88, 12)); // Orange
        linePaint.setStrokeWidth(2.5f);
        linePaint.setStyle(Paint.Style.STROKE);

        Paint dotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        dotPaint.setColor(Color.rgb(194, 65, 12));
        dotPaint.setStyle(Paint.Style.FILL);

        Path currentPath = new Path();
        boolean pathActive = false;

        for (int i = 0; i < rssiList.size(); i++) {
            long curTime = tsList.get(i);
            int curRssi = rssiList.get(i);
            double dist = Math.pow(10, (refRssi - curRssi) / (10 * 2.0));
            float clampedDist = (float) Math.min(maxDist, Math.max(0, dist));

            float x = paddingLeft + ((float) (curTime - minTime) / (float) (maxTime - minTime)) * plotWidth;
            float y = paddingTop + plotHeight - (((clampedDist - minDist) / (maxDist - minDist)) * plotHeight);

            if (i > 0) {
                long gap = curTime - tsList.get(i - 1);
                if (gap > OBSERVATION_GAP_THRESHOLD_MS) {
                    if (pathActive) {
                        canvas.drawPath(currentPath, linePaint);
                        currentPath.reset();
                        pathActive = false;
                    }
                }
            }

            if (!pathActive) {
                currentPath.moveTo(x, y);
                pathActive = true;
            } else {
                currentPath.lineTo(x, y);
            }

            canvas.drawCircle(x, y, 2.5f, dotPaint);
        }

        if (pathActive) {
            canvas.drawPath(currentPath, linePaint);
        }

        return bitmap;
    }

    /**
     * Renders Observation Sessions & Inactivity Gaps Timeline.
     */
    public static Bitmap renderTimelineGraph(DeviceReportData data, int width, int height) {
        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);

        canvas.drawColor(Color.rgb(248, 250, 252));

        Paint borderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        borderPaint.setColor(Color.rgb(203, 213, 225));
        borderPaint.setStyle(Paint.Style.STROKE);
        borderPaint.setStrokeWidth(2f);
        canvas.drawRect(1, 1, width - 1, height - 1, borderPaint);

        Paint titlePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        titlePaint.setColor(Color.rgb(15, 23, 42));
        titlePaint.setTextSize(13f);
        titlePaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText("Observation & Session Timeline (Active Windows vs Inactivity Gaps)", 20f, 22f, titlePaint);

        List<DeviceModel.ObservationSession> sessions = data.getSessions();
        long windowStart = data.getFirstObservedTimestamp();
        long windowEnd = data.getLastObservedTimestamp();

        if (windowEnd <= windowStart || sessions.isEmpty()) {
            renderInsufficientData(canvas, width, height, "Observation Timeline: Single instantaneous packet recorded");
            return bitmap;
        }

        float paddingLeft = 30f;
        float paddingRight = 30f;
        float barY = 40f;
        float barHeight = 28f;
        float barWidth = width - paddingLeft - paddingRight;

        // Background of timeline bar (Inactivity / Gaps)
        Paint gapPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        gapPaint.setColor(Color.rgb(226, 232, 240)); // Gray for gaps
        canvas.drawRoundRect(new RectF(paddingLeft, barY, paddingLeft + barWidth, barY + barHeight), 4f, 4f, gapPaint);

        // Active session blocks
        Paint sessionPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        sessionPaint.setColor(Color.rgb(22, 163, 74)); // Emerald green

        Paint sessionBorder = new Paint(Paint.ANTI_ALIAS_FLAG);
        sessionBorder.setColor(Color.rgb(21, 128, 61));
        sessionBorder.setStyle(Paint.Style.STROKE);
        sessionBorder.setStrokeWidth(1.5f);

        for (DeviceModel.ObservationSession session : sessions) {
            long sStart = Math.max(windowStart, session.getStartTime());
            long sEnd = Math.min(windowEnd, session.getEndTime());
            if (sEnd < sStart) continue;

            float xStart = paddingLeft + ((float) (sStart - windowStart) / (float) (windowEnd - windowStart)) * barWidth;
            float xEnd = paddingLeft + ((float) (sEnd - windowStart) / (float) (windowEnd - windowStart)) * barWidth;
            if (xEnd - xStart < 3f) {
                xEnd = xStart + 3f; // Minimum 3px visible width
            }

            RectF rect = new RectF(xStart, barY, xEnd, barY + barHeight);
            canvas.drawRoundRect(rect, 3f, 3f, sessionPaint);
            canvas.drawRoundRect(rect, 3f, 3f, sessionBorder);
        }

        // Ticks and labels
        Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        textPaint.setColor(Color.rgb(71, 85, 105));
        textPaint.setTextSize(10f);

        SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());
        canvas.drawText("First: " + timeFmt.format(new Date(windowStart)), paddingLeft, barY + barHeight + 16f, textPaint);
        String lastLabel = "Last: " + timeFmt.format(new Date(windowEnd));
        float lastWidth = textPaint.measureText(lastLabel);
        canvas.drawText(lastLabel, paddingLeft + barWidth - lastWidth, barY + barHeight + 16f, textPaint);

        // Legend
        Paint legendText = new Paint(Paint.ANTI_ALIAS_FLAG);
        legendText.setTextSize(9.5f);
        legendText.setColor(Color.rgb(51, 65, 85));

        canvas.drawRect(paddingLeft, height - 16f, paddingLeft + 12f, height - 6f, sessionPaint);
        canvas.drawText("Active Presence (" + data.getActivePresenceDurationFormatted() + ")", paddingLeft + 16f, height - 7f, legendText);

        float gapLegendX = paddingLeft + 170f;
        canvas.drawRect(gapLegendX, height - 16f, gapLegendX + 12f, height - 6f, gapPaint);
        canvas.drawText("Observation Gaps / Silence (" + data.getObservationGapsCount() + " gap periods, longest: " + data.getLongestGapFormatted() + ")", gapLegendX + 16f, height - 7f, legendText);

        return bitmap;
    }

    /**
     * Renders an offline schematic GPS track if Google Maps snapshot was unavailable
     * but GPS points were recorded.
     */
    public static Bitmap renderSchematicGpsTrack(DeviceReportData data, int width, int height) {
        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);

        canvas.drawColor(Color.rgb(15, 23, 42)); // Dark tactical slate

        List<TargetLocationPoint> targets = data.getTargetLocationPoints();
        List<UserLocationPoint> users = data.getUserLocationPoints();

        Paint borderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        borderPaint.setColor(Color.rgb(51, 65, 85));
        borderPaint.setStyle(Paint.Style.STROKE);
        borderPaint.setStrokeWidth(2f);
        canvas.drawRect(1, 1, width - 1, height - 1, borderPaint);

        Paint titlePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        titlePaint.setColor(Color.WHITE);
        titlePaint.setTextSize(13f);
        titlePaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        canvas.drawText("Offline Schematic Movement Plot (Google Maps Snapshot Unavailable)", 20f, 22f, titlePaint);

        if (targets.isEmpty() && users.isEmpty()) {
            renderInsufficientData(canvas, width, height, "No GPS location points recorded during observation window");
            return bitmap;
        }

        // Compute coordinate bounding box
        double minLat = Double.MAX_VALUE, maxLat = -Double.MAX_VALUE;
        double minLng = Double.MAX_VALUE, maxLng = -Double.MAX_VALUE;

        for (TargetLocationPoint p : targets) {
            minLat = Math.min(minLat, p.getLatitude());
            maxLat = Math.max(maxLat, p.getLatitude());
            minLng = Math.min(minLng, p.getLongitude());
            maxLng = Math.max(maxLng, p.getLongitude());
        }
        for (UserLocationPoint p : users) {
            minLat = Math.min(minLat, p.getLatitude());
            maxLat = Math.max(maxLat, p.getLatitude());
            minLng = Math.min(minLng, p.getLongitude());
            maxLng = Math.max(maxLng, p.getLongitude());
        }

        if (maxLat - minLat < 0.0001) {
            maxLat += 0.0001;
            minLat -= 0.0001;
        }
        if (maxLng - minLng < 0.0001) {
            maxLng += 0.0001;
            minLng -= 0.0001;
        }

        float pad = 40f;
        float plotW = width - 2 * pad;
        float plotH = height - 80f;

        // Draw User Track (Green)
        if (users.size() >= 2) {
            Paint userPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
            userPaint.setColor(Color.rgb(34, 197, 94)); // Green
            userPaint.setStrokeWidth(3f);
            userPaint.setStyle(Paint.Style.STROKE);

            Path userPath = new Path();
            for (int i = 0; i < users.size(); i++) {
                UserLocationPoint u = users.get(i);
                float x = pad + (float) ((u.getLongitude() - minLng) / (maxLng - minLng)) * plotW;
                float y = pad + 15f + plotH - (float) ((u.getLatitude() - minLat) / (maxLat - minLat)) * plotH;
                if (i == 0) userPath.moveTo(x, y);
                else userPath.lineTo(x, y);
            }
            canvas.drawPath(userPath, userPaint);
        }

        // Draw Target Observation Centers (Red)
        Paint targetPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        targetPaint.setColor(Color.rgb(239, 68, 68)); // Red
        targetPaint.setStyle(Paint.Style.FILL);

        for (TargetLocationPoint p : targets) {
            float x = pad + (float) ((p.getLongitude() - minLng) / (maxLng - minLng)) * plotW;
            float y = pad + 15f + plotH - (float) ((p.getLatitude() - minLat) / (maxLat - minLat)) * plotH;
            canvas.drawCircle(x, y, 4f, targetPaint);
        }

        // Latest range circle (Dotted Red)
        if (!targets.isEmpty()) {
            TargetLocationPoint latest = targets.get(targets.size() - 1);
            float x = pad + (float) ((latest.getLongitude() - minLng) / (maxLng - minLng)) * plotW;
            float y = pad + 15f + plotH - (float) ((latest.getLatitude() - minLat) / (maxLat - minLat)) * plotH;

            Paint rangeCirclePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
            rangeCirclePaint.setColor(Color.rgb(248, 113, 113));
            rangeCirclePaint.setStyle(Paint.Style.STROKE);
            rangeCirclePaint.setStrokeWidth(2f);
            rangeCirclePaint.setPathEffect(new DashPathEffect(new float[]{6f, 4f}, 0));
            canvas.drawCircle(x, y, 22f, rangeCirclePaint);
        }

        // Legend at bottom
        Paint legendText = new Paint(Paint.ANTI_ALIAS_FLAG);
        legendText.setTextSize(10f);
        legendText.setColor(Color.rgb(203, 213, 225));

        canvas.drawText("● Green: Investigator Phone GPS Route (" + users.size() + " pts)", pad, height - 15f, legendText);
        canvas.drawText("● Red: Device Detection Points (" + targets.size() + " pts)  |  Dotted Circle: Inferred Range Boundary", pad + 200f, height - 15f, legendText);

        return bitmap;
    }

    private static void renderInsufficientData(Canvas canvas, int width, int height, String message) {
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        p.setColor(Color.rgb(100, 116, 139));
        p.setTextSize(11f);
        p.setTextAlign(Paint.Align.CENTER);
        canvas.drawText(message, width / 2f, height / 2f, p);
    }
}
