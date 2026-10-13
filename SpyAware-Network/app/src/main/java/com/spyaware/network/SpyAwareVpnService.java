package com.spyaware.network;

import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import java.util.List;

public class SpyAwareVpnService extends VpnService {

    private static final String TAG = "SpyAwareVpn";
    public static final String ACTION_START = "com.spyaware.network.START";
    public static final String ACTION_STOP = "com.spyaware.network.STOP";

    private ParcelFileDescriptor tunInterface;
    private Thread nativeThread;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private final Runnable statsRunnable = new Runnable() {
        @Override
        public void run() {
            if (tunInterface != null) {
                StringBuilder combined = new StringBuilder();
                combined.append(PacketLog.getSummary());

                combined.append("\n--- Risk scores ---\n");
                combined.append(RiskScorer.getSummary());

                combined.append("\n--- Payload / File Analysis ---\n");
                combined.append(PacketLog.getPayloadSummary());

                broadcastStatus(combined.toString(), false);

                List<RiskScorer.AppRisk> risks = RiskScorer.scoreAll();
                RiskNotifier.checkAndNotify(SpyAwareVpnService.this, risks);

                mainHandler.postDelayed(this, 1000);
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        DetectionConfig.init(this);
        AppAttribution.init(this);
        ScreenStateMonitor.init(this);
        PersistenceManager.init(this);
        RiskNotifier.init(this);
        MuteList.init(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }
        startVpn();
        return START_STICKY;
    }

    private void startVpn() {
        if (tunInterface != null) {
            broadcastStatus("VPN already running", true);
            return;
        }

        Builder builder = new Builder();
        builder.setSession("SpyAwareNetwork")
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .setMtu(1500);

        try {
            tunInterface = builder.establish();
        } catch (Exception e) {
            Log.e(TAG, "Exception establishing VPN", e);
            broadcastStatus("VPN EXCEPTION: " + e.getMessage(), true);
            return;
        }

        if (tunInterface == null) {
            broadcastStatus("VPN FAILED to establish (null)", true);
            return;
        }

        broadcastStatus("VPN established. TUN fd: " + tunInterface.getFd(), true);

        PacketLog.reset();
        RiskNotifier.resetSession();

        final ParcelFileDescriptor tun = tunInterface;
        nativeThread = new Thread(() -> {
            try {
                NativeBridge.runLoop(tun.getFd(), SpyAwareVpnService.this);
            } catch (Throwable t) {
                Log.e(TAG, "Native loop crashed", t);
            }
        }, "ZdtunLoopThread");
        nativeThread.start();

        mainHandler.postDelayed(statsRunnable, 1000);
    }

    private void broadcastStatus(String message, boolean toast) {
        Intent intent = new Intent("com.spyaware.network.STATUS_UPDATE");
        intent.putExtra("message", message);
        intent.setPackage(getPackageName());
        sendBroadcast(intent);

        if (toast) {
            mainHandler.post(() ->
                    Toast.makeText(getApplicationContext(), message, Toast.LENGTH_SHORT).show());
        }
    }

    private void stopVpn() {
        if (tunInterface != null) {
            PersistenceManager.saveSessionSnapshot(
                    PacketLog.getStartTime(),
                    System.currentTimeMillis(),
                    PacketLog.getTotalPackets(),
                    PacketLog.getBytesSent(),
                    PacketLog.getBytesReceived(),
                    PacketLog.getFlows().size(),
                    RiskScorer.scoreAll());
        }

        mainHandler.removeCallbacks(statsRunnable);
        NativeBridge.stopLoop();

        if (nativeThread != null) {
            try {
                nativeThread.join(1500);
            } catch (InterruptedException ignored) {}
            nativeThread = null;
        }

        if (tunInterface != null) {
            try {
                tunInterface.close();
            } catch (Exception e) {
                Log.e(TAG, "Error closing TUN", e);
            }
            tunInterface = null;
        }
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        ScreenStateMonitor.shutdown(this);
        super.onDestroy();
    }
}