package com.example.spyaware.report;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;
import android.widget.Toast;

import androidx.core.content.FileProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Manages secure report export, sharing, and Storage Access Framework (SAF)
 * downloading without requesting broad or unnecessary storage permissions.
 */
public class ReportExportManager {

    private static final String TAG = "ReportExportManager";

    private ReportExportManager() {
        // Utility class
    }

    /**
     * Shares the generated PDF report via Android's standard share sheet
     * using secure content:// URI and FileProvider permissions.
     */
    public static void shareReport(Context context, File pdfFile) {
        if (context == null || pdfFile == null || !pdfFile.exists()) {
            Toast.makeText(context, "Report file not found for sharing", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            Uri contentUri = FileProvider.getUriForFile(
                    context,
                    context.getPackageName() + ".fileprovider",
                    pdfFile
            );

            Intent shareIntent = new Intent(Intent.ACTION_SEND);
            shareIntent.setType("application/pdf");
            shareIntent.putExtra(Intent.EXTRA_STREAM, contentUri);
            shareIntent.putExtra(Intent.EXTRA_SUBJECT, "SpyAware Investigation Report: " + pdfFile.getName());
            shareIntent.putExtra(Intent.EXTRA_TEXT, "Attached is the SpyAware BLE Surveillance Detection Investigation Report.");
            shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

            Intent chooser = Intent.createChooser(shareIntent, "Share Investigation Report");
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(chooser);
        } catch (Exception e) {
            Log.e(TAG, "Failed to share report: " + e.getMessage(), e);
            Toast.makeText(context, "Failed to share report: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    /**
     * Opens the generated PDF in an external viewer.
     */
    public static void openReport(Context context, File pdfFile) {
        if (context == null || pdfFile == null || !pdfFile.exists()) {
            Toast.makeText(context, "Report file not found", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            Uri contentUri = FileProvider.getUriForFile(
                    context,
                    context.getPackageName() + ".fileprovider",
                    pdfFile
            );

            Intent viewIntent = new Intent(Intent.ACTION_VIEW);
            viewIntent.setDataAndType(contentUri, "application/pdf");
            viewIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            viewIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            Intent chooser = Intent.createChooser(viewIntent, "Open Investigation Report");
            chooser.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(chooser);
        } catch (Exception e) {
            Log.e(TAG, "Failed to open report in external viewer: " + e.getMessage(), e);
            Toast.makeText(context, "No PDF viewer application found", Toast.LENGTH_SHORT).show();
        }
    }

    /**
     * Copies the PDF file to a user-selected destination URI via Storage Access Framework (SAF).
     */
    public static boolean copyReportToUri(Context context, File pdfFile, Uri destinationUri) {
        if (context == null || pdfFile == null || destinationUri == null) {
            return false;
        }

        try (InputStream in = new FileInputStream(pdfFile);
             OutputStream out = context.getContentResolver().openOutputStream(destinationUri)) {

            if (out == null) {
                return false;
            }

            byte[] buffer = new byte[8192];
            int length;
            while ((length = in.read(buffer)) > 0) {
                out.write(buffer, 0, length);
            }
            out.flush();
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Error copying report to destination URI: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Directly saves a copy of the PDF into the device's public Downloads directory
     * using MediaStore on API 29+ or public directory without broad permissions.
     */
    public static boolean saveToDownloads(Context context, File pdfFile, String displayName) {
        if (context == null || pdfFile == null || !pdfFile.exists()) {
            return false;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ContentValues values = new ContentValues();
            values.put(MediaStore.Downloads.DISPLAY_NAME, displayName);
            values.put(MediaStore.Downloads.MIME_TYPE, "application/pdf");
            values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/SpyAware");

            ContentResolver resolver = context.getContentResolver();
            Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
            if (uri == null) {
                return false;
            }
            return copyReportToUri(context, pdfFile, uri);
        } else {
            File downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            File spyAwareDir = new File(downloadsDir, "SpyAware");
            if (!spyAwareDir.exists()) {
                spyAwareDir.mkdirs();
            }
            File destFile = new File(spyAwareDir, displayName);
            try (InputStream in = new FileInputStream(pdfFile);
                 OutputStream out = new FileOutputStream(destFile)) {
                byte[] buffer = new byte[8192];
                int len;
                while ((len = in.read(buffer)) > 0) {
                    out.write(buffer, 0, len);
                }
                out.flush();
                return true;
            } catch (Exception e) {
                Log.e(TAG, "Error saving to downloads: " + e.getMessage(), e);
                return false;
            }
        }
    }
}
