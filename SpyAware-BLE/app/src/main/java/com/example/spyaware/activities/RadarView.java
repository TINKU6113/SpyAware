package com.example.spyaware.activities;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.View;

import java.util.Locale;

public class RadarView extends View {

    private final Paint paint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    // Current estimated device distance
    private float distance = 1.0f;

    // Maximum distance represented by the radar
    private float maxDistance = 50.0f;

    // Smooth animated distance
    private float displayedDistance = 1.0f;

    private String distanceText = "--";

    // Radar animation
    private float sweepAngle = 0f;

    private long lastFrameTime = 0;

    // Animation speed
    private static final float SWEEP_SPEED = 45f;

    public RadarView(Context context) {
        super(context);
        init();
    }

    public RadarView(
            Context context,
            AttributeSet attrs) {

        super(context, attrs);
        init();
    }

    public RadarView(
            Context context,
            AttributeSet attrs,
            int defStyleAttr) {

        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {

        paint.setTypeface(Typeface.DEFAULT);

        setLayerType(
                View.LAYER_TYPE_SOFTWARE,
                null
        );

        lastFrameTime =
                System.currentTimeMillis();
    }


    // ============================================================
    // SET DISTANCE
    // ============================================================

    public void setDistance(float distance) {

        if (distance < 0) {
            distance = 0;
        }

        this.distance = distance;

        distanceText =
                String.format(
                        Locale.US,
                        "%.2f m",
                        distance
                );

        invalidate();
    }


    // ============================================================
    // DRAW RADAR
    // ============================================================

    @Override
    protected void onDraw(Canvas canvas) {

        super.onDraw(canvas);

        float width = getWidth();
        float height = getHeight();

        float centerX =
                width / 2f;

        float centerY =
                height / 2f;

        float radius =
                Math.min(width, height) * 0.38f;


        // ========================================================
        // BACKGROUND
        // ========================================================

        canvas.drawColor(
                android.graphics.Color.BLACK
        );


        // ========================================================
        // RADAR RINGS
        // ========================================================

        paint.setStyle(
                Paint.Style.STROKE
        );

        paint.setStrokeWidth(3);

        paint.setColor(
                android.graphics.Color.GREEN
        );


        // ========================================================
// DISTANCE RINGS
// ========================================================

        float ring10 =
                radius * 0.20f;

        float ring20 =
                radius * 0.40f;

        float ring30 =
                radius * 0.60f;

        float ring40 =
                radius * 0.80f;

        float ring50 =
                radius;

        canvas.drawCircle(
                centerX,
                centerY,
                ring10,
                paint
        );

        canvas.drawCircle(
                centerX,
                centerY,
                ring20,
                paint
        );

        canvas.drawCircle(
                centerX,
                centerY,
                ring30,
                paint
        );

        canvas.drawCircle(
                centerX,
                centerY,
                ring40,
                paint
        );

        canvas.drawCircle(
                centerX,
                centerY,
                ring50,
                paint
        );


        // ========================================================
        // CROSSHAIR
        // ========================================================

        paint.setStrokeWidth(2);

        canvas.drawLine(
                centerX - radius,
                centerY,
                centerX + radius,
                centerY,
                paint
        );

        canvas.drawLine(
                centerX,
                centerY - radius,
                centerX,
                centerY + radius,
                paint
        );


        // ========================================================
        // RADAR SWEEP
        // ========================================================

        updateSweep();

        paint.setStyle(
                Paint.Style.STROKE
        );

        paint.setStrokeWidth(4);

        float sweepLength =
                radius * 0.95f;

        double angle =
                Math.toRadians(
                        sweepAngle
                );

        float sweepX =
                centerX +
                        (float)
                                Math.cos(angle)
                                * sweepLength;

        float sweepY =
                centerY +
                        (float)
                                Math.sin(angle)
                                * sweepLength;

        canvas.drawLine(
                centerX,
                centerY,
                sweepX,
                sweepY,
                paint
        );


        // ========================================================
        // DISTANCE NORMALIZATION
        // ========================================================

        float normalized =
                displayedDistance /
                        maxDistance;

        if (normalized < 0f) {
            normalized = 0f;
        }

        if (normalized > 1f) {
            normalized = 1f;
        }


        // ========================================================
        // DEVICE POSITION
        // ========================================================

        /*
         * For now we use a fixed angle.
         *
         * Distance determines how far the device
         * is from the scanner.
         *
         * Later we will make the angle dynamic using
         * movement/tracking information.
         */

        double deviceAngle =
                Math.toRadians(-45);

        float deviceRadius =
                normalized * radius;

        float deviceX =
                centerX +
                        (float)
                                Math.cos(deviceAngle)
                                * deviceRadius;

        float deviceY =
                centerY +
                        (float)
                                Math.sin(deviceAngle)
                                * deviceRadius;


        // ========================================================
        // DEVICE MARKER
        // ========================================================

        paint.setStyle(
                Paint.Style.FILL
        );

        paint.setColor(
                android.graphics.Color.RED
        );

        canvas.drawCircle(
                deviceX,
                deviceY,
                16,
                paint
        );


        // ========================================================
        // DEVICE GLOW
        // ========================================================

        paint.setStyle(
                Paint.Style.STROKE
        );

        paint.setStrokeWidth(4);

        canvas.drawCircle(
                deviceX,
                deviceY,
                25,
                paint
        );


        // ========================================================
        // SCANNER / PHONE
        // ========================================================

        paint.setStyle(
                Paint.Style.FILL
        );

        paint.setColor(
                android.graphics.Color.WHITE
        );

        canvas.drawCircle(
                centerX,
                centerY,
                10,
                paint
        );


        // ========================================================
// DISTANCE LABELS
// ========================================================

        paint.setColor(android.graphics.Color.WHITE);
        paint.setTextSize(16);
        paint.setTextAlign(Paint.Align.CENTER);

// 10 m
        canvas.drawText(
                "10 m",
                centerX,
                centerY - ring10 + 18,
                paint
        );

// 20 m
        canvas.drawText(
                "20 m",
                centerX,
                centerY - ring20 + 18,
                paint
        );

// 30 m
        canvas.drawText(
                "30 m",
                centerX,
                centerY - ring30 + 18,
                paint
        );

// 40 m
        canvas.drawText(
                "40 m",
                centerX,
                centerY - ring40 + 18,
                paint
        );

// 50 m
        canvas.drawText(
                "50 m",
                centerX,
                centerY - ring50 + 18,
                paint
        );


        // ========================================================
        // RING LABELS
        // ========================================================

        paint.setColor(
                android.graphics.Color.WHITE
        );

        paint.setTextSize(16);

        paint.setTextAlign(
                Paint.Align.LEFT
        );

        canvas.drawText(
                "10 m",
                centerX + ring10 + 5,
                centerY - 5,
                paint
        );

        canvas.drawText(
                "20 m",
                centerX + ring20 + 5,
                centerY - 5,
                paint
        );

        canvas.drawText(
                "30 m",
                centerX + ring30 + 5,
                centerY - 5,
                paint
        );

        canvas.drawText(
                "40 m",
                centerX + ring40 + 5,
                centerY - 5,
                paint
        );

        canvas.drawText(
                "50 m",
                centerX + ring50 - 35,
                centerY - 5,
                paint
        );


        // ========================================================
        // SMOOTH DISTANCE ANIMATION
        // ========================================================

        animateDistance();
    }


    // ============================================================
    // SMOOTH DISTANCE
    // ============================================================

    private void animateDistance() {

        float difference =
                distance - displayedDistance;

        /*
         * Move only a fraction of the difference
         * every frame.
         */

        displayedDistance +=
                difference * 0.12f;

        invalidate();
    }


    // ============================================================
    // RADAR SWEEP
    // ============================================================

    private void updateSweep() {

        long currentTime =
                System.currentTimeMillis();

        long delta =
                currentTime -
                        lastFrameTime;

        lastFrameTime =
                currentTime;

        float seconds =
                delta / 1000f;

        sweepAngle +=
                SWEEP_SPEED * seconds;

        if (sweepAngle >= 360f) {

            sweepAngle -= 360f;
        }
    }
}