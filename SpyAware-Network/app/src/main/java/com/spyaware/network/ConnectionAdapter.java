package com.spyaware.network;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Displays reconstructed flows (Stage 6) with app attribution, bytes, SNI hostname, and Stage 10 tags. */
public class ConnectionAdapter extends RecyclerView.Adapter<ConnectionAdapter.ViewHolder> {

    private List<PacketLog.Flow> items = new ArrayList<>();
    private static final long ACTIVE_MS = 5_000;

    public void submit(List<PacketLog.Flow> newItems) {
        this.items = newItems;
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_connection, parent, false);
        return new ViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        PacketLog.Flow f = items.get(position);
        boolean active = System.currentTimeMillis() - f.lastSeen <= ACTIVE_MS;

        holder.appName.setText(f.appName);
        holder.state.setText(active ? "ACTIVE" : "closed");

        String destLabel = f.sniHostname != null
                ? f.sniHostname
                : f.dstIp;
        holder.dest.setText(protoName(f.proto) + "  " + destLabel + ":" + f.dstPort);

        holder.bytes.setText(String.format(Locale.US, "out %s  in %s  pkts %d",
                fmt(f.bytesOut), fmt(f.bytesIn), f.packets));

        StringBuilder tags = new StringBuilder();
        if (f.hadBackgroundActivity) {
            tags.append("BG: ").append(fmt(f.backgroundBytes)).append("  ");
        }
        if (f.detectedFile != null
                && !"Not Available".equals(f.detectedFile.fileType)
                && !"Not Detected".equals(f.detectedFile.fileType)) {
            tags.append("File: ").append(f.detectedFile.fileType);
        }

        if (tags.length() > 0) {
            holder.tags.setVisibility(View.VISIBLE);
            holder.tags.setText(tags.toString().trim());
        } else {
            holder.tags.setVisibility(View.GONE);
        }
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    private String protoName(int proto) {
        switch (proto) {
            case 6:  return "TCP";
            case 17: return "UDP";
            case 1:  return "ICMP";
            case 58: return "ICMPv6";
            default: return "P" + proto;
        }
    }

    private String fmt(long b) {
        if (b < 1024) return b + "B";
        if (b < 1024 * 1024) return String.format(Locale.US, "%.1fKB", b / 1024.0);
        return String.format(Locale.US, "%.2fMB", b / (1024.0 * 1024.0));
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView appName, state, dest, bytes, tags;
        ViewHolder(View itemView) {
            super(itemView);
            appName = itemView.findViewById(R.id.connAppName);
            state = itemView.findViewById(R.id.connState);
            dest = itemView.findViewById(R.id.connDest);
            bytes = itemView.findViewById(R.id.connBytes);
            tags = itemView.findViewById(R.id.connTags);
        }
    }
}