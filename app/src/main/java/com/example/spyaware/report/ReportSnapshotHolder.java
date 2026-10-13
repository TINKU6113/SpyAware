package com.example.spyaware.report;

import android.graphics.Bitmap;

/**
 * In-memory transfer holder for Google Maps snapshot bitmap.
 * Avoids Android Intent Binder 1MB transaction buffer limitations
 * (TransactionTooLargeException) when passing high-resolution bitmaps
 * between activities.
 */
public class ReportSnapshotHolder {

    private static Bitmap snapshot;

    private ReportSnapshotHolder() {
    }

    public static synchronized void setSnapshot(Bitmap bitmap) {
        snapshot = bitmap;
    }

    public static synchronized Bitmap getAndClearSnapshot() {
        Bitmap temp = snapshot;
        snapshot = null;
        return temp;
    }

    public static synchronized void clear() {
        snapshot = null;
    }
}
