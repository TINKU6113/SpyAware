package com.spyaware.network;

import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Displays Stage 9 per-app risk scores as tappable cards with colored severity badges and a mute toggle. */
public class AppRiskAdapter extends RecyclerView.Adapter<AppRiskAdapter.ViewHolder> {

    private List<RiskScorer.AppRisk> items = new ArrayList<>();
    private final Set<String> expanded = new HashSet<>();

    public void submit(List<RiskScorer.AppRisk> newItems) {
        this.items = newItems;
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_app_risk, parent, false);
        return new ViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        RiskScorer.AppRisk item = items.get(position);
        holder.appName.setText(item.appName);

        boolean muted = MuteList.isMuted(item.appName);

        if (muted) {
            holder.riskBadge.setText("MUTED");
            GradientDrawable bg = (GradientDrawable) holder.riskBadge.getBackground().mutate();
            bg.setColor(Color.parseColor("#555555"));
            holder.appName.setAlpha(0.5f);
        } else {
            holder.appName.setAlpha(1.0f);
            holder.riskBadge.setText(item.score + "/100 " + item.band);

            int color;
            switch (item.band) {
                case CRITICAL: color = Color.parseColor("#D32F2F"); break;
                case HIGH:     color = Color.parseColor("#F57C00"); break;
                case MEDIUM:   color = Color.parseColor("#FBC02D"); break;
                default:       color = Color.parseColor("#388E3C"); break;
            }
            GradientDrawable bg = (GradientDrawable) holder.riskBadge.getBackground().mutate();
            bg.setColor(color);
        }

        holder.muteButton.setImageResource(muted
                ? android.R.drawable.ic_lock_silent_mode_off
                : android.R.drawable.ic_lock_silent_mode);

        boolean isExpanded = expanded.contains(item.appName);
        holder.findingsText.setVisibility(isExpanded && !muted ? View.VISIBLE : View.GONE);
        if (isExpanded && !muted) {
            StringBuilder sb = new StringBuilder();
            for (BehaviorAnalyzer.Finding f : item.findings) {
                sb.append("\u2022 ").append(f.detail).append("\n");
            }
            holder.findingsText.setText(sb.toString().trim());
        }

        holder.itemView.setOnClickListener(v -> {
            if (muted) return; // nothing to expand for a muted app
            if (expanded.contains(item.appName)) expanded.remove(item.appName);
            else expanded.add(item.appName);
            notifyDataSetChanged();
        });

        holder.muteButton.setOnClickListener(v -> {
            MuteList.setMuted(item.appName, !muted);
            notifyDataSetChanged();
        });
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView appName, riskBadge, findingsText;
        ImageButton muteButton;
        ViewHolder(View itemView) {
            super(itemView);
            appName = itemView.findViewById(R.id.appName);
            riskBadge = itemView.findViewById(R.id.riskBadge);
            findingsText = itemView.findViewById(R.id.findingsText);
            muteButton = itemView.findViewById(R.id.muteButton);
        }
    }
}