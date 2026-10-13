package com.spyaware.network.db;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.Query;

import java.util.List;

@Dao
public interface SessionDao {
    @Insert
    long insertSession(SessionEntity session);

    @Insert
    void insertAppRisks(List<AppRiskEntity> risks);

    @Query("SELECT * FROM sessions ORDER BY startTime DESC")
    List<SessionEntity> getAllSessions();

    @Query("SELECT * FROM app_risks WHERE sessionId = :sessionId ORDER BY score DESC")
    List<AppRiskEntity> getRisksForSession(long sessionId);
}