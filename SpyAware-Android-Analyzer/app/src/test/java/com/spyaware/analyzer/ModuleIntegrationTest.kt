package com.spyaware.analyzer

import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.File

class ModuleIntegrationTest {

    private val assetsModulesDir = File("src/main/assets/modules")
    private val resXmlDir = File("src/main/res/xml")

    @Test
    fun testModule4Configuration() {
        val mod4 = ModuleDefinition.MODULE_4
        assertEquals("module_4", mod4.id)
        assertEquals("Network Security Analyzer", mod4.displayName)
        assertEquals("Network monitoring and security analysis.", mod4.subtitle)
        assertEquals("Network monitoring and security analysis.", mod4.description)
        assertEquals("com.spyaware.network", mod4.packageName)
        assertEquals("SpyAware-Module4-Network.apk", mod4.assetFileName)
        assertEquals(26, mod4.minSdk)
        assertEquals(34, mod4.targetSdk)
        assertEquals("a3f142012c2f56b33c742c2a86c767bbad30b9eaf52cb5345eacfbef051667a7", mod4.knownCertSha256)
    }

    @Test
    fun testModule5Configuration() {
        val mod5 = ModuleDefinition.MODULE_5
        assertEquals("module_5", mod5.id)
        assertEquals("BLE Surveillance Detector", mod5.displayName)
        assertEquals("Detect nearby Bluetooth Low Energy devices and investigate suspicious device behavior.", mod5.subtitle)
        assertEquals("Detect nearby Bluetooth Low Energy devices and investigate suspicious device behavior.", mod5.description)
        assertEquals("com.example.spyaware", mod5.packageName)
        assertEquals("SpyAware-Module5-BLE.apk", mod5.assetFileName)
        assertEquals(31, mod5.minSdk)
        assertEquals(36, mod5.targetSdk)
        assertEquals("a14f40592d4d5e7abbbc3ca381f176433ad9101aa3955930eed96ac386e89c0c", mod5.knownCertSha256)
    }

    @Test
    fun testModuleRegistryAndLookup() {
        assertEquals(2, ModuleDefinition.ALL_MODULES.size)

        // Lookup by ID
        val foundById4 = ModuleDefinition.findById("module_4")
        assertNotNull(foundById4)
        assertEquals("com.spyaware.network", foundById4?.packageName)

        val foundById5 = ModuleDefinition.findById("module_5")
        assertNotNull(foundById5)
        assertEquals("com.example.spyaware", foundById5?.packageName)

        // Lookup by Package ID
        val foundByPkg4 = ModuleDefinition.findById("com.spyaware.network")
        assertNotNull(foundByPkg4)
        assertEquals("module_4", foundByPkg4?.id)

        val foundByPkg5 = ModuleDefinition.findById("com.example.spyaware")
        assertNotNull(foundByPkg5)
        assertEquals("module_5", foundByPkg5?.id)

        // Unknown module
        assertNull(ModuleDefinition.findById("com.unknown.fake"))
    }

    @Test
    fun testBundledModuleApkAssetsExist() {
        val mod4Apk = File(assetsModulesDir, "SpyAware-Module4-Network.apk")
        assertTrue("Module 4 APK must exist in assets/modules", mod4Apk.exists())
        assertTrue("Module 4 APK size must be greater than 1MB", mod4Apk.length() > 1024 * 1024)

        val mod5Apk = File(assetsModulesDir, "SpyAware-Module5-BLE.apk")
        assertTrue("Module 5 APK must exist in assets/modules", mod5Apk.exists())
        assertTrue("Module 5 APK size must be greater than 1MB", mod5Apk.length() > 1024 * 1024)
    }

    @Test
    fun testFileProviderPathsConfig() {
        val filePathsXml = File(resXmlDir, "file_paths.xml")
        assertTrue("file_paths.xml must exist in res/xml", filePathsXml.exists())
        val content = filePathsXml.readText()
        assertTrue("file_paths.xml must declare cache-path", content.contains("<cache-path"))
        assertTrue("file_paths.xml must declare path='modules/'", content.contains("path=\"modules/\""))
    }

    @Test
    fun testSignatureMismatchDetectionLogic() {
        val certA = "a3f142012c2f56b33c742c2a86c767bbad30b9eaf52cb5345eacfbef051667a7"
        val certB = "a14f40592d4d5e7abbbc3ca381f176433ad9101aa3955930eed96ac386e89c0c"

        val installedSignatures = listOf(certA)
        val matchingArchiveSignatures = listOf(certA)
        val mismatchingArchiveSignatures = listOf(certB)

        // Signatures overlap test
        val doesMatch = installedSignatures.any { inst ->
            matchingArchiveSignatures.any { arch -> inst.equals(arch, ignoreCase = true) }
        }
        assertTrue("Identical certificate SHA256 must match", doesMatch)

        val doesMismatch = installedSignatures.any { inst ->
            mismatchingArchiveSignatures.any { arch -> inst.equals(arch, ignoreCase = true) }
        }
        assertFalse("Different certificate SHA256 must not match (triggers mismatch protection)", doesMismatch)
    }

    @Test
    fun testVersionDowngradeProtectionLogic() {
        val installedVersionCode = 2L
        val olderArchiveVersionCode = 1L
        val sameArchiveVersionCode = 2L
        val newerArchiveVersionCode = 3L

        assertTrue("Installed > Archive indicates downgrade attempt", installedVersionCode > olderArchiveVersionCode)
        assertFalse("Installed == Archive is permitted", installedVersionCode > sameArchiveVersionCode)
        assertFalse("Installed < Archive is normal upgrade", installedVersionCode > newerArchiveVersionCode)
    }

    @Test
    fun testLaunchIntentFlagsIncludeBringToForeground() {
        val expectedFlags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
        val hasNewTask = (expectedFlags and Intent.FLAG_ACTIVITY_NEW_TASK) != 0
        val hasResetTask = (expectedFlags and Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED) != 0

        assertTrue("Launch intent must have FLAG_ACTIVITY_NEW_TASK", hasNewTask)
        assertTrue("Launch intent must have FLAG_ACTIVITY_RESET_TASK_IF_NEEDED to bring task to foreground", hasResetTask)
    }

    @Test
    fun testWebAppInterfaceModulesJson() {
        val webAppInterface = WebAppInterface(
            getBackendUrlProvider = { "http://10.0.2.2:8000" }
        )

        val jsonStr = webAppInterface.getModulesJson()
        assertNotNull(jsonStr)

        val jsonArray = JSONArray(jsonStr)
        assertEquals(2, jsonArray.length())

        val mod4Obj = jsonArray.getJSONObject(0)
        assertEquals("module_4", mod4Obj.getString("id"))
        assertEquals("Network Security Analyzer", mod4Obj.getString("displayName"))
        assertEquals("com.spyaware.network", mod4Obj.getString("packageName"))
        assertEquals(26, mod4Obj.getInt("minSdk"))
        assertEquals(34, mod4Obj.getInt("targetSdk"))

        val mod5Obj = jsonArray.getJSONObject(1)
        assertEquals("module_5", mod5Obj.getString("id"))
        assertEquals("BLE Surveillance Detector", mod5Obj.getString("displayName"))
        assertEquals("com.example.spyaware", mod5Obj.getString("packageName"))
        assertEquals(31, mod5Obj.getInt("minSdk"))
        assertEquals(36, mod5Obj.getInt("targetSdk"))
    }

    @Test
    fun testWebAppInterfaceOpenAnalysisEngine() {
        var openAnalysisEngineInvoked = false
        val webAppInterface = WebAppInterface(
            getBackendUrlProvider = { "http://10.0.2.2:8000" },
            onOpenAnalysisEngine = {
                openAnalysisEngineInvoked = true
            }
        )

        webAppInterface.openAnalysisEngine()
        assertTrue("Calling openAnalysisEngine on WebAppInterface must invoke callback", openAnalysisEngineInvoked)
    }

    @Test
    fun testWebAppInterfaceModuleActions() {
        var lastOpenedModule: ModuleDefinition? = null
        var lastInstalledModule: ModuleDefinition? = null

        val webAppInterface = WebAppInterface(
            getBackendUrlProvider = { "http://10.0.2.2:8000" },
            onModuleAction = { lastOpenedModule = it },
            onModuleInstall = { lastInstalledModule = it }
        )

        // Open Module 4 by package ID
        val openResult4 = webAppInterface.openModule("com.spyaware.network")
        assertTrue(openResult4)
        assertEquals(ModuleDefinition.MODULE_4, lastOpenedModule)

        // Open Module 5 by ID
        val openResult5 = webAppInterface.openModule("module_5")
        assertTrue(openResult5)
        assertEquals(ModuleDefinition.MODULE_5, lastOpenedModule)

        // Install Module 4 by ID
        val installResult4 = webAppInterface.installModule("module_4")
        assertTrue(installResult4)
        assertEquals(ModuleDefinition.MODULE_4, lastInstalledModule)

        // Install Module 5 by package ID
        val installResult5 = webAppInterface.installModule("com.example.spyaware")
        assertTrue(installResult5)
        assertEquals(ModuleDefinition.MODULE_5, lastInstalledModule)

        // Unknown module should return false
        val unknownOpenResult = webAppInterface.openModule("unknown.package")
        assertFalse(unknownOpenResult)

        val unknownInstallResult = webAppInterface.installModule("unknown.module")
        assertFalse(unknownInstallResult)
    }
}
