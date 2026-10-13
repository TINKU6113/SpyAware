package com.spyaware.network;

import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.spyaware.network.db.SessionEntity;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HistoryActivity extends AppCompatActivity {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_history);

        PersistenceManager.init(this);

        RecyclerView list = findViewById(R.id.sessionList);
        SessionAdapter adapter = new SessionAdapter();
        list.setLayoutManager(new LinearLayoutManager(this));
        list.setAdapter(adapter);

        executor.execute(() -> {
            List<SessionEntity> sessions = PersistenceManager.getAllSessionsSync();
            runOnUiThread(() -> adapter.submit(sessions));
        });
    }
}