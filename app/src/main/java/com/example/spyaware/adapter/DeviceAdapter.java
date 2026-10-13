package com.example.spyaware.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import com.example.spyaware.security.RiskEngine;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.spyaware.R;
import com.example.spyaware.model.DeviceModel;

import java.util.List;

public class DeviceAdapter
        extends RecyclerView.Adapter<DeviceAdapter.DeviceViewHolder> {

    public interface OnDeviceClickListener {
        void onDeviceClick(DeviceModel device);
    }

    public interface OnDeviceActionListener {
        void onViewDetails(DeviceModel device);
        void onGenerateReport(DeviceModel device);
    }

    private List<DeviceModel> deviceList;
    private OnDeviceClickListener listener;
    private OnDeviceActionListener actionListener;

    public DeviceAdapter(
            List<DeviceModel> deviceList,
            OnDeviceClickListener listener) {

        this.deviceList = deviceList;
        this.listener = listener;
    }

    public DeviceAdapter(
            List<DeviceModel> deviceList,
            OnDeviceActionListener actionListener) {

        this.deviceList = deviceList;
        this.actionListener = actionListener;
    }

    public void setOnDeviceActionListener(OnDeviceActionListener actionListener) {
        this.actionListener = actionListener;
    }

    @NonNull
    @Override
    public DeviceViewHolder onCreateViewHolder(
            @NonNull ViewGroup parent,
            int viewType) {

        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.device_item, parent, false);

        return new DeviceViewHolder(view);
    }

    @Override
    public void onBindViewHolder(
            @NonNull DeviceViewHolder holder,
            int position) {

        DeviceModel device = deviceList.get(position);
        // =====================================================
// DEVICE RISK / CARD COLOR
// =====================================================

        String riskLevel =
                device.getRiskLevel();

        int riskScore =
                device.getRiskScore();

        holder.tvRisk.setText(
                "Risk: "
                        + riskLevel
                        + " ("
                        + riskScore
                        + "/100)"
        );
        // =====================================================
// CARD COLOR
// =====================================================

        if (device.isKnownDevice()) {

            // Trusted device
            holder.deviceCard.setBackgroundColor(
                    android.graphics.Color.rgb(
                            200,
                            255,
                            200
                    )
            );

        } else if (
                RiskEngine.HIGH.equals(riskLevel) ||
                        RiskEngine.CRITICAL.equals(riskLevel)
        ) {

            // High-risk unknown device
            holder.deviceCard.setBackgroundColor(
                    android.graphics.Color.rgb(
                            255,
                            180,
                            180
                    )
            );

        } else {

            // Normal unknown device
            holder.deviceCard.setBackgroundColor(
                    android.graphics.Color.WHITE
            );
        }
        // =====================================================
// TEXT COLOR
// =====================================================

        if (device.isKnownDevice()) {

            // Known / trusted
            holder.tvDeviceName.setTextColor(
                    android.graphics.Color.rgb(0, 100, 0)
            );

            holder.tvMac.setTextColor(
                    android.graphics.Color.DKGRAY
            );

            holder.tvRssi.setTextColor(
                    android.graphics.Color.DKGRAY
            );

            holder.tvRisk.setTextColor(
                    android.graphics.Color.rgb(0, 100, 0)
            );

            holder.tvLastSeen.setTextColor(
                    android.graphics.Color.DKGRAY
            );

        } else if (
                RiskEngine.HIGH.equals(riskLevel) ||
                        RiskEngine.CRITICAL.equals(riskLevel)
        ) {

            // High / Critical unknown device
            holder.tvDeviceName.setTextColor(
                    android.graphics.Color.rgb(120, 0, 0)
            );

            holder.tvMac.setTextColor(
                    android.graphics.Color.rgb(70, 0, 0)
            );

            holder.tvRssi.setTextColor(
                    android.graphics.Color.rgb(70, 0, 0)
            );

            holder.tvRisk.setTextColor(
                    android.graphics.Color.rgb(120, 0, 0)
            );

            holder.tvLastSeen.setTextColor(
                    android.graphics.Color.rgb(70, 0, 0)
            );

        } else {

            // Normal unknown device
            holder.tvDeviceName.setTextColor(
                    android.graphics.Color.BLACK
            );

            holder.tvMac.setTextColor(
                    android.graphics.Color.DKGRAY
            );

            holder.tvRssi.setTextColor(
                    android.graphics.Color.DKGRAY
            );

            holder.tvRisk.setTextColor(
                    android.graphics.Color.BLACK
            );

            holder.tvLastSeen.setTextColor(
                    android.graphics.Color.DKGRAY
            );
        }

        holder.tvDeviceName.setText(
                device.getDeviceName()
        );

        holder.tvMac.setText(
                "MAC : " + device.getMacAddress()
        );

        holder.tvRssi.setText(
                "RSSI : " + device.getRssi() + " dBm"
        );

        holder.tvLastSeen.setText(
                "First Seen : " + device.getFirstSeen()
                        + "\nLast Seen : " + device.getLastSeen()
                        + "\nPackets : " + device.getPacketCount()

                        + "\nManufacturer : "
                        + device.getManufacturerData()

                        + "\nServices : "
                        + device.getServiceUuids()

                        + "\nTX Power : "
                        + formatTxPower(device.getTxPower())

                        + "\nFingerprint : "
                        + device.getBleFingerprint().substring(
                        0,
                        Math.min(
                                16,
                                device.getBleFingerprint().length()
                        )
                )

                        + "\nAverage RSSI : "
                        + String.format(
                        java.util.Locale.US,
                        "%.1f dBm",
                        device.getAverageRssi()
                )

                        + "\nRSSI Range : "
                        + device.getMinimumRssi()
                        + " to "
                        + device.getMaximumRssi()

                        + "\nProximity : "
                        + device.getProximityState()
                        + "\nEstimated Distance : "
                        + String.format(
                        java.util.Locale.US,
                        "%.2f m",
                        device.getEstimatedDistance()
                )
                        + "\nRSSI Trend : "
                        + device.getRssiTrend()

                        + "\nAvg Interval : "
                        + String.format(
                        java.util.Locale.US,
                        "%.0f ms",
                        device.getAverageIntervalMs()
                )
                        + "\nDuration : "
                        + device.getObservationDurationFormatted()

                        + "\nPersistence : "
                        + device.getPersistenceState()

                        + "\nClassification : "
                        + device.getDeviceClassification()

                        + "\nRisk : "
                        + device.getRiskLevel()

                        + "\nRisk Score : "
                        + device.getRiskScore()
                        + "/100"
        );
        holder.itemView.setOnClickListener(v -> {
            if (actionListener != null) {
                actionListener.onViewDetails(device);
            } else if (listener != null) {
                listener.onDeviceClick(device);
            }
        });

        if (holder.btnViewDetails != null) {
            holder.btnViewDetails.setOnClickListener(v -> {
                if (actionListener != null) {
                    actionListener.onViewDetails(device);
                } else if (listener != null) {
                    listener.onDeviceClick(device);
                }
            });
        }

        if (holder.btnGenerateReport != null) {
            holder.btnGenerateReport.setOnClickListener(v -> {
                if (actionListener != null) {
                    actionListener.onGenerateReport(device);
                }
            });
        }
    }

    private String formatTxPower(int txPower) {

        if (txPower == Integer.MIN_VALUE) {
            return "Unknown";
        }

        return txPower + " dBm";
    }

    @Override
    public int getItemCount() {
        return deviceList.size();
    }

    public static class DeviceViewHolder
            extends RecyclerView.ViewHolder {

        TextView tvDeviceName;
        TextView tvMac;
        TextView tvRssi;
        TextView tvLastSeen;
        View deviceCard;
        TextView tvRisk;
        android.widget.Button btnViewDetails;
        android.widget.Button btnGenerateReport;

        public DeviceViewHolder(
                @NonNull View itemView) {

            super(itemView);

            tvDeviceName =
                    itemView.findViewById(R.id.tvDeviceName);

            tvMac =
                    itemView.findViewById(R.id.tvMac);

            tvRssi =
                    itemView.findViewById(R.id.tvRssi);

            tvRisk =
                    itemView.findViewById(R.id.tvRisk);

            tvLastSeen =
                    itemView.findViewById(R.id.tvLastSeen);

            deviceCard =
                    itemView.findViewById(R.id.deviceCard);

            btnViewDetails =
                    itemView.findViewById(R.id.btnViewDetails);

            btnGenerateReport =
                    itemView.findViewById(R.id.btnGenerateReport);
        }
    }
}