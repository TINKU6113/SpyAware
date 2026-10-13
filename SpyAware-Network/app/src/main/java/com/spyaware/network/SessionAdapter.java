package com.spyaware.network;

import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.spyaware.network.db.AppRiskEntity;
import com.spyaware.network.db.SessionEntity;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SessionAdapter extends RecyclerView.Adapter<SessionAdapter.ViewHolder> {

    private List<SessionEntity> sessions = new ArrayList<>();
    private final Set<Long> expanded = new HashSet<>();
    private final Map<Long, List<AppRiskEntity>> riskCache = new HashMap<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private static final SimpleDateFormat DATE_FMT = new SimpleDateFormat("MMM d, HH:mm", Locale.US);

    public void submit(List<SessionEntity> newSessions) {
        this.sessions = newSessions;
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_session, parent, false);
        return new ViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        SessionEntity s = sessions.get(position);
        holder.title.setText(DATE_FMT.format(new Date(s.startTime)));

        long durationSec = (s.endTime - s.startTime) / 1000;
        holder.stats.setText(String.format(Locale.US,
                "Duration %ds   Packets %d   Sent %s   Received %s   Connections %d",
                durationSec, s.totalPackets, fmt(s.bytesSent), fmt(s.bytesReceived), s.connectionCount));

        boolean isExpanded = expanded.contains(s.id);
        holder.risks.setVisibility(isExpanded ? View.VISIBLE : View.GONE);

        if (isExpanded) {
            List<AppRiskEntity> cached = riskCache.get(s.id);
            if (cached != null) {
                holder.risks.setText(formatRisks(cached));
            } else {
                holder.risks.setText("Loading...");
                final int pos = holder.getBindingAdapterPosition();
                executor.execute(() -> {
                    List<AppRiskEntity> risks = PersistenceManager.getRisksForSessionSync(s.id);
                    riskCache.put(s.id, risks);
                    mainHandler.post(() -> notifyItemChanged(pos));
                });
            }
        }

        holder.itemView.setOnClickListener(v -> {
            if (expanded.contains(s.id)) expanded.remove(s.id);
            else expanded.add(s.id);
            notifyItemChanged(holder.getBindingAdapterPosition());
        });
    }

    private String formatRisks(List<AppRiskEntity> risks) {
        if (risks.isEmpty()) return "No risk findings this session.";
        StringBuilder sb = new StringBuilder();
        for (AppRiskEntity r : risks) {
            sb.append(r.appName).append(": ").append(r.score).append("/100 [").append(r.band).append("]\n");
            if (r.findingsText != null && !r.findingsText.isEmpty()) {
                for (String line : r.findingsText.split("\n")) {
                    sb.append("   - ").append(line).append("\n");
                }
            }
        }
        return sb.toString().trim();
    }

    private String fmt(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return String.format(Locale.US, "%.1f KB", b / 1024.0);
        return String.format(Locale.US, "%.2f MB", b / (1024.0 * 1024.0));
    }

    @Override
    public int getItemCount() {
        return sessions.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView title, stats, risks;
        ViewHolder(View itemView) {
            super(itemView);
            title = itemView.findViewById(R.id.sessionTitle);
            stats = itemView.findViewById(R.id.sessionStats);
            risks = itemView.findViewById(R.id.sessionRisks);
        }
    }
}