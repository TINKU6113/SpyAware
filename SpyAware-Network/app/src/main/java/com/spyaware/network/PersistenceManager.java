package com.spyaware.network;

import android.content.Context;

import com.spyaware.network.db.AppDatabase;
import com.spyaware.network.db.AppRiskEntity;
import com.spyaware.network.db.SessionEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Saves a session snapshot (stats + per-app risk scores) to Room when the VPN stops. Best-effort: failures here never crash the VPN service. */
public class PersistenceManager {

    private static AppDatabase db;
    private static final ExecutorService executor = Executors.newSingleThreadExecutor();

    public static void init(Context context) {
        if (db == null) {
            db = AppDatabase.getInstance(context);
        }
    }

    public static void saveSessionSnapshot(long startTime, long endTime, long totalPackets,
                                           long bytesSent, long bytesReceived, int connectionCount,
                                           List<RiskScorer.AppRisk> risks) {
        if (db == null) return;

        executor.execute(() -> {
            try {
                SessionEntity session = new SessionEntity();
                session.startTime = startTime;
                session.endTime = endTime;
                session.totalPackets = totalPackets;
                session.bytesSent = bytesSent;
                session.bytesReceived = bytesReceived;
                session.connectionCount = connectionCount;

                long sessionId = db.sessionDao().insertSession(session);

                List<AppRiskEntity> entities = new ArrayList<>();
                for (RiskScorer.AppRisk r : risks) {
                    AppRiskEntity e = new AppRiskEntity();
                    e.sessionId = sessionId;
                    e.appName = r.appName;
                    e.score = r.score;
                    e.band = r.band.name();

                    StringBuilder sb = new StringBuilder();
                    for (BehaviorAnalyzer.Finding f : r.findings) {
                        sb.append(f.detail).append("\n");
                    }
                    e.findingsText = sb.toString().trim();
                    entities.add(e);
                }
                if (!entities.isEmpty()) {
                    db.sessionDao().insertAppRisks(entities);
                }
            } catch (Exception ignored) {
                // best-effort persistence
            }
        });
    }

    /** Synchronous -- call from a background thread only (see HistoryActivity/SessionAdapter). */
    public static List<SessionEntity> getAllSessionsSync() {
        if (db == null) return new ArrayList<>();
        return db.sessionDao().getAllSessions();
    }

    public static List<AppRiskEntity> getRisksForSessionSync(long sessionId) {
        if (db == null) return new ArrayList<>();
        return db.sessionDao().getRisksForSession(sessionId);
    }
}