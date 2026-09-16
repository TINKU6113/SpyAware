package com.example.spyaware.activities;

import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.spyaware.R;
import com.example.spyaware.model.KnownDevice;
import com.example.spyaware.model.KnownDeviceRegistry;

import java.util.ArrayList;
import java.util.List;

public class KnownDevicesActivity extends AppCompatActivity {

    private ListView listKnownDevices;

    private KnownDeviceRegistry knownDeviceRegistry;

    private ArrayAdapter<String> adapter;

    private final List<String> deviceDisplayList =
            new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_known_devices);

        // =====================================================
        // INITIALIZE REGISTRY
        // =====================================================

        knownDeviceRegistry =
                KnownDeviceRegistry.getInstance();

        // =====================================================
        // UI
        // =====================================================

        listKnownDevices =
                findViewById(R.id.listKnownDevices);

        adapter =
                new ArrayAdapter<>(
                        this,
                        android.R.layout.simple_list_item_1,
                        deviceDisplayList
                );

        listKnownDevices.setAdapter(adapter);

        // =====================================================
        // LOAD KNOWN DEVICES
        // =====================================================

        loadKnownDevices();

        // =====================================================
        // LONG PRESS = REMOVE DEVICE
        // =====================================================

        listKnownDevices.setOnItemLongClickListener(
                (parent, view, position, id) -> {

                    List<KnownDevice> devices =
                            knownDeviceRegistry.getKnownDevices();

                    // Prevent selecting the
                    // "No known devices" text
                    if (position >= devices.size()) {
                        return true;
                    }

                    KnownDevice device =
                            devices.get(position);

                    boolean removed =
                            knownDeviceRegistry
                                    .removeByFingerprint(
                                            device.getFingerprint()
                                    );

                    if (removed) {

                        Toast.makeText(
                                this,
                                device.getName()
                                        + " removed",
                                Toast.LENGTH_SHORT
                        ).show();

                        loadKnownDevices();
                    }

                    return true;
                }
        );
    }

    // =====================================================
    // LOAD DEVICES
    // =====================================================

    private void loadKnownDevices() {

        deviceDisplayList.clear();

        List<KnownDevice> devices =
                knownDeviceRegistry.getKnownDevices();

        if (devices.isEmpty()) {

            deviceDisplayList.add(
                    "No known devices registered"
            );

        } else {

            for (KnownDevice device : devices) {

                String text =
                        device.getName()
                                + "\n"
                                + "Fingerprint: "
                                + device.getFingerprint()
                                + "\n"
                                + "Reference RSSI: "
                                + device
                                .getReferenceRssiAtOneMeter()
                                + " dBm"
                                + "\n\n"
                                + "Long press to remove";

                deviceDisplayList.add(text);
            }
        }

        adapter.notifyDataSetChanged();
    }
}