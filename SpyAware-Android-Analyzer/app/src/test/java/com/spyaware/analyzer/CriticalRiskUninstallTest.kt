package com.spyaware.analyzer

import android.content.Intent
import android.net.Uri
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CriticalRiskUninstallTest {

    private lateinit var handler: CriticalRiskUninstallHandler
    private var isTargetInstalled = true
    private var launchedIntent: Intent? = null
    private var dialogShownForPackage: String? = null
    private var dialogConfirmAction: ((String) -> Unit)? = null
    private var dialogCancelAction: (() -> Unit)? = null

    private fun buildReportJson(
        riskLevel: String = "CRITICAL",
        analysisStatus: String = "COMPLETED_WITH_FINDINGS",
        analysisId: String = "analysis-test-uuid-1",
        staticPackageName: String? = null
    ): String {
        return JSONObject().apply {
            put("analysis_id", analysisId)
            put("risk_level", riskLevel)
            put("analysis_status", analysisStatus)
            put("overall_score", when (riskLevel) {
                "CRITICAL" -> 85.0
                "HIGH" -> 65.0
                "MEDIUM" -> 35.0
                "LOW" -> 15.0
                else -> 0.0
            })
            if (staticPackageName != null) {
                put("static_details", JSONObject().apply {
                    put("package_name", staticPackageName)
                })
            }
        }.toString()
    }

    @Before
    fun setUp() {
        isTargetInstalled = true
        launchedIntent = null
        dialogShownForPackage = null
        dialogConfirmAction = null
        dialogCancelAction = null

        handler = CriticalRiskUninstallHandler(
            context = null,
            isPackageInstalledProvider = { isTargetInstalled },
            dialogLauncher = { pkg, onConfirm, onCancel ->
                dialogShownForPackage = pkg
                dialogConfirmAction = onConfirm
                dialogCancelAction = onCancel
            },
            activityLauncher = { intent ->
                launchedIntent = intent
            }
        )
    }

    // 1. CRITICAL result for an installed application displays the uninstall confirmation dialog.
    @Test
    fun testCriticalResultForInstalledAppDisplaysDialog() {
        val criticalJson = buildReportJson(riskLevel = "CRITICAL", analysisId = "crit-101")
        val pkg = "com.suspicious.stalkerware"

        val evaluation = handler.shouldPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = criticalJson,
            currentAppPackageName = "com.spyaware.analyzer"
        )

        assertTrue("Evaluation must be Prompt for CRITICAL risk", evaluation is CriticalRiskUninstallHandler.EvaluationResult.Prompt)
        val prompt = evaluation as CriticalRiskUninstallHandler.EvaluationResult.Prompt
        assertEquals(pkg, prompt.packageName)
        assertEquals("crit-101", prompt.analysisId)
        assertEquals("CRITICAL", prompt.riskLevel)

        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = criticalJson
        )
        assertTrue("checkAndPromptUninstall must return true for CRITICAL risk", shown)
        assertEquals(pkg, dialogShownForPackage)
        assertNotNull("Confirm action must be set", dialogConfirmAction)
        assertNotNull("Cancel action must be set", dialogCancelAction)
    }

    // 2. HIGH result does not display the dialog.
    @Test
    fun testHighResultDoesNotDisplayDialog() {
        val highJson = buildReportJson(riskLevel = "HIGH", analysisId = "high-201")
        val pkg = "com.suspicious.app"

        assertFalse("isCriticalRisk must be false for HIGH", handler.isCriticalRisk(highJson))

        val evaluation = handler.shouldPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = highJson,
            currentAppPackageName = "com.spyaware.analyzer"
        )
        assertTrue("Evaluation must be DoNotPrompt for HIGH risk", evaluation is CriticalRiskUninstallHandler.EvaluationResult.DoNotPrompt)

        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = highJson
        )
        assertFalse("checkAndPromptUninstall must return false for HIGH risk", shown)
        assertNull("Dialog must not be displayed for HIGH risk", dialogShownForPackage)
    }

    // 3. MEDIUM result does not display the dialog.
    @Test
    fun testMediumResultDoesNotDisplayDialog() {
        val mediumJson = buildReportJson(riskLevel = "MEDIUM", analysisId = "med-301")
        val pkg = "com.suspicious.app"

        assertFalse("isCriticalRisk must be false for MEDIUM", handler.isCriticalRisk(mediumJson))

        val evaluation = handler.shouldPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = mediumJson,
            currentAppPackageName = "com.spyaware.analyzer"
        )
        assertTrue("Evaluation must be DoNotPrompt for MEDIUM risk", evaluation is CriticalRiskUninstallHandler.EvaluationResult.DoNotPrompt)

        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = mediumJson
        )
        assertFalse("checkAndPromptUninstall must return false for MEDIUM risk", shown)
        assertNull("Dialog must not be displayed for MEDIUM risk", dialogShownForPackage)
    }

    // 4. LOW result does not display the dialog.
    @Test
    fun testLowResultDoesNotDisplayDialog() {
        val lowJson = buildReportJson(riskLevel = "LOW", analysisId = "low-401")
        val pkg = "com.benign.app"

        assertFalse("isCriticalRisk must be false for LOW", handler.isCriticalRisk(lowJson))

        val evaluation = handler.shouldPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = lowJson,
            currentAppPackageName = "com.spyaware.analyzer"
        )
        assertTrue("Evaluation must be DoNotPrompt for LOW risk", evaluation is CriticalRiskUninstallHandler.EvaluationResult.DoNotPrompt)

        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = lowJson
        )
        assertFalse("checkAndPromptUninstall must return false for LOW risk", shown)
        assertNull("Dialog must not be displayed for LOW risk", dialogShownForPackage)
    }

    // 5. Failed analysis does not display the dialog.
    @Test
    fun testFailedAnalysisDoesNotDisplayDialog() {
        val failedJson = buildReportJson(riskLevel = "CRITICAL", analysisStatus = "FAILED")
        assertFalse("Failed analysis status must not be classified as critical risk", handler.isCriticalRisk(failedJson))

        val inconclusiveJson = buildReportJson(riskLevel = "CRITICAL", analysisStatus = "INCONCLUSIVE")
        assertFalse("Inconclusive analysis must not trigger critical risk", handler.isCriticalRisk(inconclusiveJson))

        val malformedJson = "{not-valid-json"
        assertFalse("Malformed JSON must not trigger critical risk", handler.isCriticalRisk(malformedJson))

        val emptyJson = ""
        assertFalse("Empty string must not trigger critical risk", handler.isCriticalRisk(emptyJson))

        val nullJson: String? = null
        assertFalse("Null response must not trigger critical risk", handler.isCriticalRisk(nullJson))

        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = "com.some.app",
            responseJson = failedJson
        )
        assertFalse("checkAndPromptUninstall must return false for failed analysis", shown)
        assertNull("Dialog must not be shown for failed analysis", dialogShownForPackage)
    }

    // 6. Uploaded APK analysis does not trigger installed-app uninstall confirmation.
    @Test
    fun testUploadedApkAnalysisDoesNotTriggerUninstallConfirmation() {
        val criticalJson = buildReportJson(riskLevel = "CRITICAL")
        val pkg = "com.uploaded.apk"

        val evaluation = handler.shouldPromptUninstall(
            isInstalledApp = false,
            packageName = pkg,
            responseJson = criticalJson,
            currentAppPackageName = "com.spyaware.analyzer"
        )
        assertTrue("Evaluation must be DoNotPrompt for uploaded APK", evaluation is CriticalRiskUninstallHandler.EvaluationResult.DoNotPrompt)
        val doNotPrompt = evaluation as CriticalRiskUninstallHandler.EvaluationResult.DoNotPrompt
        assertTrue(doNotPrompt.reason.contains("Not an installed application"))

        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = false,
            packageName = pkg,
            responseJson = criticalJson
        )
        assertFalse("checkAndPromptUninstall must return false for uploaded APK", shown)
        assertNull("Dialog must not be shown for uploaded APK", dialogShownForPackage)
    }

    // 7. CANCEL never launches the uninstall intent.
    @Test
    fun testCancelNeverLaunchesUninstallIntent() {
        val criticalJson = buildReportJson(riskLevel = "CRITICAL", analysisId = "crit-cancel-test")
        val pkg = "com.suspicious.stalkerware"

        var cancelCallbackInvoked = false
        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = pkg,
            responseJson = criticalJson,
            onCancelled = {
                cancelCallbackInvoked = true
            }
        )
        assertTrue(shown)
        assertNotNull(dialogCancelAction)

        // Simulate user clicking CANCEL
        dialogCancelAction?.invoke()

        assertTrue("Cancel callback must be invoked when user cancels", cancelCallbackInvoked)
        assertNull("Uninstall intent must NEVER be launched when user cancels", launchedIntent)
        assertNull("Pending uninstall package must remain null on cancel", handler.pendingUninstallPackageName)
    }

    // 8. UNINSTALL targets the exact analyzed application's package.
    @Test
    fun testUninstallTargetsExactAnalyzedApplicationPackage() {
        val criticalJson = buildReportJson(riskLevel = "CRITICAL", analysisId = "crit-uninstall-test")
        val targetPkg = "com.covert.spyware.tracker"

        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = targetPkg,
            responseJson = criticalJson
        )
        assertTrue(shown)
        assertEquals(targetPkg, dialogShownForPackage)
        assertNotNull(dialogConfirmAction)

        // Simulate user clicking UNINSTALL
        dialogConfirmAction?.invoke(targetPkg)

        assertNotNull("Uninstall intent must be launched when user confirms", launchedIntent)
        assertEquals(targetPkg, handler.pendingUninstallPackageName)

        // Verify the uninstallation intent properties
        assertEquals(Intent.ACTION_DELETE, handler.getUninstallIntentAction())
        assertEquals("android.intent.action.DELETE", handler.getUninstallIntentAction())
        assertEquals("package:$targetPkg", handler.getUninstallPackageUriString(targetPkg))
        val intent = handler.createUninstallIntent(targetPkg)
        assertNotNull("createUninstallIntent must return a valid Intent instance", intent)
    }

    // 9. SpyAware cannot uninstall itself through this workflow.
    @Test
    fun testSpyAwareCannotUninstallItself() {
        val spyAwarePkg = "com.spyaware.analyzer"
        val criticalJson = buildReportJson(riskLevel = "CRITICAL")

        val validation = handler.validatePackageForUninstall(
            packageName = spyAwarePkg,
            currentAppPackageName = spyAwarePkg
        )
        assertTrue("SpyAware package validation must be Invalid", validation is CriticalRiskUninstallHandler.ValidationResult.Invalid)

        val evaluation = handler.shouldPromptUninstall(
            isInstalledApp = true,
            packageName = spyAwarePkg,
            responseJson = criticalJson,
            currentAppPackageName = spyAwarePkg
        )
        assertTrue("Evaluation must be DoNotPrompt for SpyAware package", evaluation is CriticalRiskUninstallHandler.EvaluationResult.DoNotPrompt)

        val shown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = spyAwarePkg,
            responseJson = criticalJson
        )
        assertFalse("checkAndPromptUninstall must reject self-uninstallation", shown)
        assertNull("Dialog must not be shown for SpyAware itself", dialogShownForPackage)

        val launchResult = handler.launchUninstallIntent(spyAwarePkg)
        assertFalse("launchUninstallIntent must return false when targeting SpyAware", launchResult)
        assertNull("Intent must not be launched for SpyAware itself", launchedIntent)
    }

    // 10. Invalid or missing package names are handled safely.
    @Test
    fun testInvalidOrMissingPackageNamesHandledSafely() {
        val criticalJson = buildReportJson(riskLevel = "CRITICAL")

        // Missing / empty package
        val nullPkgValidation = handler.validatePackageForUninstall(null)
        assertTrue(nullPkgValidation is CriticalRiskUninstallHandler.ValidationResult.Invalid)

        val emptyPkgValidation = handler.validatePackageForUninstall("")
        assertTrue(emptyPkgValidation is CriticalRiskUninstallHandler.ValidationResult.Invalid)

        val blankPkgValidation = handler.validatePackageForUninstall("   ")
        assertTrue(blankPkgValidation is CriticalRiskUninstallHandler.ValidationResult.Invalid)

        // Malformed package name
        val malformedValidation = handler.validatePackageForUninstall("not_a_valid_package_name")
        assertTrue(malformedValidation is CriticalRiskUninstallHandler.ValidationResult.Invalid)

        val invalidCharsValidation = handler.validatePackageForUninstall("com.app;rm -rf")
        assertTrue(invalidCharsValidation is CriticalRiskUninstallHandler.ValidationResult.Invalid)

        // Mismatched package name with report static_details
        val mismatchedJson = buildReportJson(riskLevel = "CRITICAL", staticPackageName = "com.other.package")
        val mismatchValidation = handler.validatePackageForUninstall(
            packageName = "com.target.package",
            responseJsonStr = mismatchedJson
        )
        assertTrue(mismatchValidation is CriticalRiskUninstallHandler.ValidationResult.Invalid)
        val mismatchReason = (mismatchValidation as CriticalRiskUninstallHandler.ValidationResult.Invalid).reason
        assertTrue(mismatchReason.contains("Mismatched package name"))

        // Package not installed on device
        isTargetInstalled = false
        val notInstalledEval = handler.shouldPromptUninstall(
            isInstalledApp = true,
            packageName = "com.uninstalled.app",
            responseJson = criticalJson
        )
        assertTrue(notInstalledEval is CriticalRiskUninstallHandler.EvaluationResult.DoNotPrompt)
        val reason = (notInstalledEval as CriticalRiskUninstallHandler.EvaluationResult.DoNotPrompt).reason
        assertTrue(reason.contains("not installed"))
    }

    // 11. Returning from the system uninstall screen does not produce a repeated dialog.
    @Test
    fun testReturningFromSystemUninstallScreenDoesNotProduceRepeatedDialog() {
        val criticalJson = buildReportJson(riskLevel = "CRITICAL", analysisId = "crit-duplicate-test-1")
        val targetPkg = "com.suspicious.app"

        // Step 1: Initial analysis shows dialog
        val firstShown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = targetPkg,
            responseJson = criticalJson
        )
        assertTrue("First prompt must succeed", firstShown)
        assertEquals("crit-duplicate-test-1", handler.lastPromptedAnalysisId)

        // Step 2: User confirms uninstall -> launches system screen
        dialogConfirmAction?.invoke(targetPkg)
        assertEquals(targetPkg, handler.pendingUninstallPackageName)

        // Step 3: Same analysis result evaluated again (e.g. onResume or duplicate trigger)
        val secondShown = handler.checkAndPromptUninstall(
            isInstalledApp = true,
            packageName = targetPkg,
            responseJson = criticalJson
        )
        assertFalse("Duplicate analysis ID must not display dialog again", secondShown)

        // Step 4: Resume lifecycle check when app was NOT uninstalled (user cancelled in system UI)
        isTargetInstalled = true
        var stillInstalledNotified = false
        var uninstalledNotified = false

        handler.handleResume(
            onAppUninstalled = { uninstalledNotified = true },
            onAppStillInstalled = { stillInstalledNotified = true }
        )

        assertTrue("Must notify that app is still installed when user cancelled system UI", stillInstalledNotified)
        assertFalse("Must NOT claim app was uninstalled when it is still installed", uninstalledNotified)
        assertNull("pendingUninstallPackageName must be cleared after resume handling", handler.pendingUninstallPackageName)

        // Step 5: Resume lifecycle check when app WAS uninstalled
        handler.pendingUninstallPackageName = targetPkg
        isTargetInstalled = false
        var confirmedUninstalled = false

        handler.handleResume(
            onAppUninstalled = { confirmedUninstalled = true }
        )

        assertTrue("Must notify confirmed uninstallation after checking package is gone", confirmedUninstalled)
    }

    // 12. Existing analysis and module-launching functionality remains intact.
    @Test
    fun testExistingAnalysisAndModuleIntegrationsIntact() {
        // Module definitions remain accessible
        assertEquals(2, ModuleDefinition.ALL_MODULES.size)
        assertNotNull(ModuleDefinition.findById("module_4"))
        assertNotNull(ModuleDefinition.findById("module_5"))

        // Installed App Manager validations remain correct
        assertTrue(InstalledAppManager.isValidPackageName("com.example.app"))
        assertFalse(InstalledAppManager.isValidPackageName("invalid..pkg"))

        // Handler state reset works properly
        handler.lastPromptedAnalysisId = "old-id"
        handler.lastPromptedPackage = "com.old.pkg"
        handler.pendingUninstallPackageName = "com.pending.pkg"

        handler.resetPromptState()
        assertNull(handler.lastPromptedAnalysisId)
        assertNull(handler.lastPromptedPackage)
        assertNull(handler.pendingUninstallPackageName)
    }
}
