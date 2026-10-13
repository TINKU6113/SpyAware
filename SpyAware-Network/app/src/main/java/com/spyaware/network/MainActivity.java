package com.spyaware.network;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import java.util.List;
import java.util.Locale;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.core.content.ContextCompat;

public class MainActivity extends AppCompatActivity {

    private TextView summaryText;
    private Button startButton;
    private AppRiskAdapter appRiskAdapter;
    private ConnectionAdapter connectionAdapter;

    private boolean vpnRunning = false;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private final Runnable refreshRunnable = new Runnable() {
        @Override
        public void run() {
            refreshDashboard();
            mainHandler.postDelayed(this, 1000);
        }
    };

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String message = intent.getStringExtra("message");
            if (message == null) return;
            if (message.contains("established") || message.contains("FAILED")
                    || message.contains("EXCEPTION") || message.contains("already running")) {
                summaryText.setText(message);
            }
        }
    };

    private final ActivityResultLauncher<Intent> vpnPermissionLauncher =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
                if (result.getResultCode() == RESULT_OK) {
                    startVpnService();
                } else {
                    summaryText.setText("VPN permission denied");
                }
            });
    private final ActivityResultLauncher<String> notificationPermissionLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestPermission(), granted -> {
                // No action needed either way -- the dashboard still works without it,
                // notifications simply won't show if denied.
            });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        PersistenceManager.init(this);
        MuteList.init(this);

        summaryText = findViewById(R.id.summaryText);
        startButton = findViewById(R.id.startButton);
        Button historyButton = findViewById(R.id.historyButton);

        RecyclerView appRiskList = findViewById(R.id.appRiskList);
        appRiskAdapter = new AppRiskAdapter();
        appRiskList.setLayoutManager(new LinearLayoutManager(this));
        appRiskList.setAdapter(appRiskAdapter);

        RecyclerView connectionList = findViewById(R.id.connectionList);
        connectionAdapter = new ConnectionAdapter();
        connectionList.setLayoutManager(new LinearLayoutManager(this));
        connectionList.setAdapter(connectionAdapter);

        startButton.setOnClickListener(v -> {
            if (vpnRunning) {
                stopVpnService();
            } else {
                requestVpnPermission();
            }
        });

        historyButton.setOnClickListener(v ->
                startActivity(new Intent(MainActivity.this, HistoryActivity.class)));

        IntentFilter filter = new IntentFilter("com.spyaware.network.STATUS_UPDATE");
        registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS);
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        mainHandler.post(refreshRunnable);
    }

    @Override
    protected void onPause() {
        super.onPause();
        mainHandler.removeCallbacks(refreshRunnable);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(statusReceiver);
    }

    private void requestVpnPermission() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            vpnPermissionLauncher.launch(intent);
        } else {
            startVpnService();
        }
    }

    private void startVpnService() {
        Intent serviceIntent = new Intent(this, SpyAwareVpnService.class);
        serviceIntent.setAction(SpyAwareVpnService.ACTION_START);
        startService(serviceIntent);
        vpnRunning = true;
        startButton.setText("Stop");
        summaryText.setText("Starting VPN...");
    }

    private void stopVpnService() {
        Intent serviceIntent = new Intent(this, SpyAwareVpnService.class);
        serviceIntent.setAction(SpyAwareVpnService.ACTION_STOP);
        startService(serviceIntent);
        vpnRunning = false;
        startButton.setText("Start");
        summaryText.setText("VPN stopped");
    }

    private void refreshDashboard() {
        List<PacketLog.Flow> flows = PacketLog.getFlows();
        List<RiskScorer.AppRisk> risks = RiskScorer.scoreAll();

        connectionAdapter.submit(flows);
        appRiskAdapter.submit(risks);

        if (vpnRunning) {
            long seconds = (System.currentTimeMillis() - PacketLog.getStartTime()) / 1000;
            summaryText.setText(String.format(Locale.US,
                    "Packets: %d   Sent: %s   Received: %s   Duration: %ds   Screen: %s",
                    PacketLog.getTotalPackets(),
                    fmt(PacketLog.getBytesSent()),
                    fmt(PacketLog.getBytesReceived()),
                    seconds,
                    ScreenStateMonitor.isScreenOn() ? "ON" : "OFF"));
        }
    }

    private String fmt(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return String.format(Locale.US, "%.1f KB", b / 1024.0);
        return String.format(Locale.US, "%.2f MB", b / (1024.0 * 1024.0));
    }
}