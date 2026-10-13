package com.spyaware.network;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

/**
 * Stage 7: maps a connection (protocol, local ip:port, remote ip:port)
 * to the Android app that owns it, using ConnectivityManager.getConnectionOwnerUid
 * (requires API 29+), then resolves the UID to a human-readable app label.
 */
public class AppAttribution {

    private static final String TAG = "AppAttribution";

    private static ConnectivityManager connectivityManager;
    private static PackageManager packageManager;

    // UID -> app label cache, so we don't hit PackageManager on every flow
    private static final Map<Integer, String> uidNameCache = new HashMap<>();

    public static void init(Context context) {
        Context appContext = context.getApplicationContext();
        connectivityManager = (ConnectivityManager)
                appContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        packageManager = appContext.getPackageManager();
    }

    /**
     * @param proto      6 = TCP, 17 = UDP (the OS API only supports these two)
     * @param localIp    device-side IP as seen in the captured packet (our TUN address)
     * @param remoteIp   destination IP of the connection
     */
    public static synchronized String resolve(int proto, String localIp, int localPort,
                                              String remoteIp, int remotePort) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return "N/A";
        }
        if (connectivityManager == null) {
            return "N/A";
        }
        if (proto != 6 && proto != 17) {
            return "-"; // ICMP etc. has no owning socket
        }

        try {
            InetSocketAddress local = new InetSocketAddress(localIp, localPort);
            InetSocketAddress remote = new InetSocketAddress(remoteIp, remotePort);

            int uid = connectivityManager.getConnectionOwnerUid(proto, local, remote);

            if (uid == -1 || uid == Process.INVALID_UID) {
                return "Unknown";
            }
            return nameForUid(uid);
        } catch (Exception e) {
            Log.e(TAG, "resolve failed", e);
            return "Unknown";
        }
    }

    private static String nameForUid(int uid) {
        String cached = uidNameCache.get(uid);
        if (cached != null) return cached;

        String result;
        try {
            String[] packages = packageManager.getPackagesForUid(uid);
            if (packages == null || packages.length == 0) {
                result = "uid:" + uid;
            } else {
                ApplicationInfo appInfo = packageManager.getApplicationInfo(packages[0], 0);
                result = packageManager.getApplicationLabel(appInfo).toString();
            }
        } catch (Exception e) {
            result = "uid:" + uid;
        }

        uidNameCache.put(uid, result);
        return result;
    }
}