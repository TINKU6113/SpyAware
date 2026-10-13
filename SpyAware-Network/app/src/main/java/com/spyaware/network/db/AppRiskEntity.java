package com.spyaware.network.db;

import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "app_risks")
public class AppRiskEntity {
    @PrimaryKey(autoGenerate = true)
    public long id;

    public long sessionId;
    public String appName;
    public int score;
    public String band;
    public String findingsText; // finding details, one per line
}