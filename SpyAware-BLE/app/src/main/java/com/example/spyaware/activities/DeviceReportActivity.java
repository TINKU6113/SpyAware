package com.example.spyaware.activities;

import android.graphics.Bitmap;
import android.graphics.pdf.PdfRenderer;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.example.spyaware.R;
import com.example.spyaware.bluetooth.BleDeviceRegistry;
import com.example.spyaware.model.DeviceModel;
import com.example.spyaware.report.DeviceReportData;
import com.example.spyaware.report.DeviceReportGenerator;
import com.example.spyaware.report.ReportExportManager;
import com.example.spyaware.report.ReportSnapshotHolder;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Activity presenting an interactive, visual preview of the generated PDF report
 * with options to choose download location via Storage Access Framework (SAF),
 * share through standard Android share sheet, or open in external viewers.
 */
public class DeviceReportActivity extends AppCompatActivity {

    private String deviceIdentifier;
    private DeviceModel targetDevice;
    private DeviceReportData reportData;
    private File generatedPdfFile;

    private LinearLayout layoutProgress;
    private LinearLayout layoutContent;
    private LinearLayout pagesContainer;
    private TextView tvReportSubtitle;
    private TextView tvReportSummary;
    private TextView tvReportIdBadge;
    private TextView tvProgressMessage;

    private Button btnClose;
    private Button btnDownload;
    private Button btnShare;
    private Button btnOpen;

    private final List<Bitmap> renderedBitmaps = new ArrayList<>();

    // SAF Document Creation Launcher
    private final ActivityResultLauncher<String> createDocumentLauncher =
            registerForActivityResult(new ActivityResultContracts.CreateDocument("application/pdf"), uri -> {
                if (uri != null && generatedPdfFile != null) {
                    boolean success = ReportExportManager.copyReportToUri(this, generatedPdfFile, uri);
                    if (success) {
                        Toast.makeText(this, "Report saved successfully!", Toast.LENGTH_LONG).show();
                    } else {
                        Toast.makeText(this, "Failed to write report to selected location", Toast.LENGTH_LONG).show();
                    }
                }
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_device_report);

        layoutProgress = findViewById(R.id.layoutProgress);
        layoutContent = findViewById(R.id.layoutContent);
        pagesContainer = findViewById(R.id.pagesContainer);
        tvReportSubtitle = findViewById(R.id.tvReportSubtitle);
        tvReportSummary = findViewById(R.id.tvReportSummary);
        tvReportIdBadge = findViewById(R.id.tvReportIdBadge);
        tvProgressMessage = findViewById(R.id.tvProgressMessage);

        btnClose = findViewById(R.id.btnClose);
        btnDownload = findViewById(R.id.btnDownload);
        btnShare = findViewById(R.id.btnShare);
        btnOpen = findViewById(R.id.btnOpen);

        btnClose.setOnClickListener(v -> finish());

        deviceIdentifier = getIntent().getStringExtra("deviceIdentifier");
        if (deviceIdentifier == null || deviceIdentifier.isEmpty()) {
            showError("Missing device identifier");
            return;
        }

        targetDevice = findDevice(deviceIdentifier);
        if (targetDevice == null) {
            showError("Selected device (" + deviceIdentifier + ") not found in active registry");
            return;
        }

        tvReportSubtitle.setText(targetDevice.getDeviceName() + " (" + targetDevice.getMacAddress() + ")");

        // Retrieve any captured Google Maps snapshot
        Bitmap mapSnapshot = ReportSnapshotHolder.getAndClearSnapshot();

        // Compile report data
        reportData = DeviceReportData.fromDeviceModel(targetDevice, MainActivity.userLocationHistory);
        if (mapSnapshot != null) {
            reportData.setMapSnapshotBitmap(mapSnapshot);
            reportData.setMapSnapshotStatus("Google Maps satellite snapshot captured and verified.");
        }

        // Generate report asynchronously
        generateReport();
    }

    private DeviceModel findDevice(String identifier) {
        DeviceModel d = BleDeviceRegistry.getDevice(identifier);
        if (d != null) {
            return d;
        }
        if (MainActivity.deviceList != null) {
            for (DeviceModel dev : MainActivity.deviceList) {
                if (identifier.equals(dev.getMacAddress()) || identifier.equals(dev.getBleFingerprint())) {
                    return dev;
                }
            }
        }
        return null;
    }

    private void generateReport() {
        layoutProgress.setVisibility(View.VISIBLE);
        layoutContent.setVisibility(View.GONE);
        tvProgressMessage.setText("Compiling Observation Analytics & Generating Vector PDF...");

        DeviceReportGenerator.generateReportAsync(this, reportData, new DeviceReportGenerator.ReportGenerationCallback() {
            @Override
            public void onSuccess(File pdfFile, DeviceReportData data) {
                generatedPdfFile = pdfFile;
                onReportGenerated(pdfFile, data);
            }

            @Override
            public void onError(Exception error) {
                showError("Report generation failed: " + error.getMessage());
            }
        });
    }

    private void onReportGenerated(File pdfFile, DeviceReportData data) {
        layoutProgress.setVisibility(View.GONE);
        layoutContent.setVisibility(View.VISIBLE);

        tvReportIdBadge.setText(data.getReportId());
        tvReportSummary.setText(String.format(Locale.US, "3 Pages • %.1f KB • %s",
                (pdfFile.length() / 1024f), data.getRiskLevel() + " Risk"));

        // Render PDF pages to screen for interactive preview
        renderPdfPagesToUi(pdfFile);

        // Download (SAF)
        btnDownload.setOnClickListener(v -> {
            String safeId = data.getDeviceIdentifier().replaceAll("[^a-zA-Z0-9_-]", "_");
            String defaultFileName = "SpyAware_Report_" + safeId + "_" + data.getReportId() + ".pdf";
            createDocumentLauncher.launch(defaultFileName);
        });

        // Share
        btnShare.setOnClickListener(v -> {
            ReportExportManager.shareReport(DeviceReportActivity.this, pdfFile);
        });

        // Open in external viewer
        btnOpen.setOnClickListener(v -> {
            ReportExportManager.openReport(DeviceReportActivity.this, pdfFile);
        });
    }

    private void renderPdfPagesToUi(File pdfFile) {
        pagesContainer.removeAllViews();
        renderedBitmaps.clear();

        try {
            ParcelFileDescriptor pfd = ParcelFileDescriptor.open(pdfFile, ParcelFileDescriptor.MODE_READ_ONLY);
            PdfRenderer renderer = new PdfRenderer(pfd);

            int pageCount = renderer.getPageCount();
            for (int i = 0; i < pageCount; i++) {
                PdfRenderer.Page page = renderer.openPage(i);

                // Render at 1.5x resolution for sharp display
                int w = (int) (page.getWidth() * 1.5f);
                int h = (int) (page.getHeight() * 1.5f);
                Bitmap bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
                page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY);
                page.close();

                renderedBitmaps.add(bitmap);

                // Page Container Card
                LinearLayout card = new LinearLayout(this);
                card.setOrientation(LinearLayout.VERTICAL);
                card.setBackgroundColor(0xFFFFFFFF);
                LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                cardParams.setMargins(0, 0, 0, 24);
                card.setLayoutParams(cardParams);
                card.setElevation(8f);

                ImageView pageView = new ImageView(this);
                pageView.setAdjustViewBounds(true);
                pageView.setImageBitmap(bitmap);
                card.addView(pageView);

                // Page Label
                TextView pageNum = new TextView(this);
                pageNum.setText("Page " + (i + 1) + " of " + pageCount);
                pageNum.setTextColor(0xFF64748B);
                pageNum.setTextSize(11f);
                pageNum.setPadding(16, 8, 16, 12);
                card.addView(pageNum);

                pagesContainer.addView(card);
            }

            renderer.close();
            pfd.close();
        } catch (Exception e) {
            TextView errorText = new TextView(this);
            errorText.setText("PDF preview rendering unavailable (" + e.getMessage() + "), but PDF was successfully generated.");
            errorText.setTextColor(0xFFCBD5E1);
            pagesContainer.addView(errorText);
        }
    }

    private void showError(String message) {
        layoutProgress.setVisibility(View.GONE);
        layoutContent.setVisibility(View.GONE);
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        for (Bitmap b : renderedBitmaps) {
            if (b != null && !b.isRecycled()) {
                b.recycle();
            }
        }
        renderedBitmaps.clear();
    }
}
