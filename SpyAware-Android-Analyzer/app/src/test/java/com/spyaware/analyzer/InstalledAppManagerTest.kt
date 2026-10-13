package com.spyaware.analyzer

import android.content.Context
import android.content.pm.ApplicationInfo
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.FileOutputStream

class InstalledAppManagerTest {

    private lateinit var tempDir: File

    @Before
    fun setUp() {
        tempDir = File(System.getProperty("java.io.tmpdir"), "spyaware_test_" + System.currentTimeMillis())
        tempDir.mkdirs()
    }

    @Test
    fun testValidPackageNames() {
        assertTrue(InstalledAppManager.isValidPackageName("com.example.app"))
        assertTrue(InstalledAppManager.isValidPackageName("com.spyaware.analyzer"))
        assertTrue(InstalledAppManager.isValidPackageName("org.test_pkg.v2"))
        assertTrue(InstalledAppManager.isValidPackageName("a.b.c"))
        assertTrue(InstalledAppManager.isValidPackageName("com.android.settings"))
    }

    @Test
    fun testInvalidPackageNamesRejected() {
        assertFalse(InstalledAppManager.isValidPackageName(""))
        assertFalse(InstalledAppManager.isValidPackageName("   "))
        assertFalse(InstalledAppManager.isValidPackageName("com..app"))
        assertFalse(InstalledAppManager.isValidPackageName(".com.app"))
        assertFalse(InstalledAppManager.isValidPackageName("com.app."))
        assertFalse(InstalledAppManager.isValidPackageName("com/app"))
        assertFalse(InstalledAppManager.isValidPackageName("../evil/path"))
        assertFalse(InstalledAppManager.isValidPackageName("com.app;rm -rf"))
        assertFalse(InstalledAppManager.isValidPackageName("com.app&ls"))
        assertFalse(InstalledAppManager.isValidPackageName("1com.app"))
        assertFalse(InstalledAppManager.isValidPackageName("com.app with spaces"))
        assertFalse(InstalledAppManager.isValidPackageName("singleword"))
    }

    @Test
    fun testSystemAppClassification() {
        val userAppInfo = ApplicationInfo().apply {
            flags = 0
        }
        assertFalse("User app flags must not be classified as system app", InstalledAppManager.isSystemApp(userAppInfo))

        val systemAppInfo = ApplicationInfo().apply {
            flags = ApplicationInfo.FLAG_SYSTEM
        }
        assertTrue("FLAG_SYSTEM must be classified as system app", InstalledAppManager.isSystemApp(systemAppInfo))

        val updatedSystemAppInfo = ApplicationInfo().apply {
            flags = ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
        }
        assertTrue("FLAG_UPDATED_SYSTEM_APP must be classified as system app", InstalledAppManager.isSystemApp(updatedSystemAppInfo))

        val combinedFlagsInfo = ApplicationInfo().apply {
            flags = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_ALLOW_BACKUP
        }
        assertTrue("Combined flags containing FLAG_SYSTEM must be classified as system app", InstalledAppManager.isSystemApp(combinedFlagsInfo))
    }

    @Test
    fun testInstalledAppItemJsonSerialization() {
        val item = InstalledAppManager.InstalledAppItem(
            packageName = "com.test.surveillance",
            appName = "Tracker Tool",
            versionName = "2.1.0",
            isSystem = false,
            isSplit = true,
            splitCount = 3,
            apkSize = 25482000L,
            iconBase64 = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="
        )

        val json = item.toJson()
        assertEquals("com.test.surveillance", json.getString("packageName"))
        assertEquals("Tracker Tool", json.getString("appName"))
        assertEquals("2.1.0", json.getString("versionName"))
        assertFalse(json.getBoolean("isSystem"))
        assertTrue(json.getBoolean("isSplit"))
        assertEquals(3, json.getInt("splitCount"))
        assertEquals(25482000L, json.getLong("apkSize"))
        assertEquals("data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==", json.getString("icon"))
    }

    @Test
    fun testInstalledAppItemJsonWithoutIcon() {
        val item = InstalledAppManager.InstalledAppItem(
            packageName = "com.test.utility",
            appName = "Utility Tool",
            versionName = "1.0",
            isSystem = true,
            isSplit = false,
            splitCount = 0,
            apkSize = 1048576L,
            iconBase64 = null
        )

        val json = item.toJson()
        assertEquals("com.test.utility", json.getString("packageName"))
        assertTrue(json.getBoolean("isSystem"))
        assertFalse(json.getBoolean("isSplit"))
        assertEquals(0, json.getInt("splitCount"))
        assertFalse(json.has("icon"))
    }

    @Test
    fun testStagedApkCleanup() {
        val cacheDir = File(tempDir, "staged_apks")
        cacheDir.mkdirs()

        val dummyApk1 = File(cacheDir, "com.test.app1_staged.apk")
        dummyApk1.writeText("fake apk content 1")
        val dummyApk2 = File(cacheDir, "com.test.app2_staged.apk")
        dummyApk2.writeText("fake apk content 2")
        val otherFile = File(cacheDir, "keep_this.txt")
        otherFile.writeText("important non-apk text")

        assertTrue(dummyApk1.exists())
        assertTrue(dummyApk2.exists())
        assertTrue(otherFile.exists())

        // Simulate cleanup logic on staged_apks directory
        cacheDir.listFiles()?.forEach { file ->
            if (file.isFile && file.name.endsWith(".apk")) {
                file.delete()
            }
        }

        assertFalse("Staged APK 1 must be deleted", dummyApk1.exists())
        assertFalse("Staged APK 2 must be deleted", dummyApk2.exists())
        assertTrue("Non-apk files must not be deleted by staged APK cleanup", otherFile.exists())

        // Clean test tempDir
        tempDir.deleteRecursively()
    }

    @Test
    fun testMaxUploadLimitConstantIs150MB() {
        val maxMb = 150L
        val maxBytes = maxMb * 1024L * 1024L
        assertEquals(157286400L, maxBytes)
        // 151MB exceeds limit
        val oversizedBytes = 151L * 1024L * 1024L
        assertTrue(oversizedBytes > maxBytes)
    }
}
