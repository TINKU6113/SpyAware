package com.spyaware.network.db;

import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "sessions")
public class SessionEntity {
    @PrimaryKey(autoGenerate = true)
    public long id;

    public long startTime;
    public long endTime;
    public long totalPackets;
    public long bytesSent;
    public long bytesReceived;
    public int connectionCount;
}