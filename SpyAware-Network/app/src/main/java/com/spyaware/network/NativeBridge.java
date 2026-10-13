package com.spyaware.network;

import android.net.VpnService;

public class NativeBridge {
    static {
        System.loadLibrary("spyawarenative");
    }

    public static native void runLoop(int tunFd, VpnService vpnService);
    public static native void stopLoop();
    public static native String getStats();   // NEW
}