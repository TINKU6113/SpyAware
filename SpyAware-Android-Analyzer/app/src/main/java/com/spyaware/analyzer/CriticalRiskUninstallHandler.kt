package com.spyaware.analyzer

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.json.JSONObject

/**
 * Manages the safety workflow when an installed application is classified as CRITICAL risk.
 *
 * Provides detection of CRITICAL risk classifications from backend analysis reports,
 * package validation (preventing invalid packages, mismatched packages, and self-uninstallation),
 * presentation of the native Material 3 uninstall confirmation dialog, launching of
 * Android's official system uninstall intent (ACTION_DELETE), and lifecycle-safe resumption.
 */
class CriticalRiskUninstallHandler(
    private val context: Context? = null,
    private val isPackageInstalledProvider: ((String) -> Boolean)? = null,
    private val dialogLauncher: ((packageName: String, onConfirm: (String) -> Unit, onCancel: () -> Unit) -> Unit)? = null,
    private val activityLauncher: ((Intent) -> Unit)? = null
) {

    sealed class ValidationResult {
        object Valid : ValidationResult()
        data class Invalid(val reason: String) : ValidationResult()
    }

    sealed class EvaluationResult {
        data class Prompt(
            val packageName: String,
            val analysisId: String,
            val riskLevel: String
        ) : EvaluationResult()

        data class DoNotPrompt(val reason: String) : EvaluationResult()
    }

    // State tracking for duplicate prevention and lifecycle resumption
    var lastPromptedAnalysisId: String? = null
    var lastPromptedPackage: String? = null
    var pendingUninstallPackageName: String? = null
    var activeDialog: AlertDialog? = null

    /**
     * Checks if a package is currently installed on the device.
     */
    fun isPackageInstalled(packageName: String): Boolean {
        isPackageInstalledProvider?.let { return it(packageName) }
        val ctx = context ?: return false
        return InstalledAppManager.isPackageInstalled(ctx, packageName)
    }

    /**
     * Checks if the analysis report indicates a valid CRITICAL risk level.
     * Rejects missing, malformed, non-CRITICAL, or failed analyses.
     */
    fun isCriticalRisk(responseJson: String?): Boolean {
        if (responseJson.isNullOrBlank()) return false
        return try {
            val json = JSONObject(responseJson)
            val analysisStatus = json.optString("analysis_status", "").trim().uppercase()
            if (analysisStatus == "FAILED" || analysisStatus == "INCONCLUSIVE") {
                return false
            }
            val riskLevel = json.optString("risk_level", "").trim().uppercase()
            riskLevel == "CRITICAL"
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Validates that the target package name is valid, does not target SpyAware itself,
     * and matches the report if static_details contains package_name.
     */
    fun validatePackageForUninstall(
        packageName: String?,
        currentAppPackageName: String = context?.packageName ?: "com.spyaware.analyzer",
        responseJsonStr: String? = null
    ): ValidationResult {
        if (packageName.isNullOrBlank()) {
            return ValidationResult.Invalid("Package name is missing or blank")
        }

        val trimmed = packageName.trim()
        if (!InstalledAppManager.isValidPackageName(trimmed)) {
            return ValidationResult.Invalid("Invalid package name format: '$trimmed'")
        }

        if (trimmed.equals(currentAppPackageName.trim(), ignoreCase = true) ||
            trimmed.equals("com.spyaware.analyzer", ignoreCase = true)
        ) {
            return ValidationResult.Invalid("Target package cannot be SpyAware Analyzer ($trimmed)")
        }

        if (!responseJsonStr.isNullOrBlank()) {
            try {
                val json = JSONObject(responseJsonStr)
                val staticDetails = json.optJSONObject("static_details")
                val reportPkg = staticDetails?.optString("package_name")?.trim()
                if (!reportPkg.isNullOrEmpty() && !reportPkg.equals(trimmed, ignoreCase = true)) {
                    return ValidationResult.Invalid("Mismatched package name: analyzed '$trimmed' but report contains '$reportPkg'")
                }
            } catch (_: Exception) {
                // Malformed JSON handled in evaluation
            }
        }

        return ValidationResult.Valid
    }

    /**
     * Evaluates whether an uninstall prompt should be shown.
     */
    fun shouldPromptUninstall(
        isInstalledApp: Boolean,
        packageName: String?,
        responseJson: String?,
        currentAppPackageName: String = context?.packageName ?: "com.spyaware.analyzer"
    ): EvaluationResult {
        if (!isInstalledApp) {
            return EvaluationResult.DoNotPrompt("Not an installed application analysis workflow")
        }

        val validation = validatePackageForUninstall(packageName, currentAppPackageName, responseJson)
        if (validation is ValidationResult.Invalid) {
            return EvaluationResult.DoNotPrompt(validation.reason)
        }

        val targetPackage = packageName!!.trim()

        if (!isPackageInstalled(targetPackage)) {
            return EvaluationResult.DoNotPrompt("Application '$targetPackage' is not installed on device")
        }

        if (!isCriticalRisk(responseJson)) {
            return EvaluationResult.DoNotPrompt("Analysis risk level is not CRITICAL")
        }

        val analysisId = try {
            JSONObject(responseJson!!).optString("analysis_id", "").trim()
        } catch (_: Exception) {
            ""
        }

        if (analysisId.isNotEmpty() && analysisId == lastPromptedAnalysisId) {
            return EvaluationResult.DoNotPrompt("Analysis ID '$analysisId' has already been prompted")
        }

        if (analysisId.isEmpty() && targetPackage == lastPromptedPackage) {
            return EvaluationResult.DoNotPrompt("Package '$targetPackage' has already been prompted for this analysis")
        }

        if (activeDialog?.isShowing == true) {
            return EvaluationResult.DoNotPrompt("An uninstall confirmation dialog is already displayed")
        }

        return EvaluationResult.Prompt(
            packageName = targetPackage,
            analysisId = analysisId,
            riskLevel = "CRITICAL"
        )
    }

    /**
     * Builds the standard system uninstallation intent.
     */
    fun getUninstallPackageUriString(packageName: String): String = "package:${packageName.trim()}"

    fun getUninstallIntentAction(): String = Intent.ACTION_DELETE

    fun createUninstallIntent(packageName: String): Intent {
        val trimmed = packageName.trim()
        return Intent(getUninstallIntentAction()).apply {
            data = Uri.parse(getUninstallPackageUriString(trimmed))
        }
    }

    /**
     * Evaluates the completed analysis result and displays the confirmation dialog if CRITICAL.
     */
    fun checkAndPromptUninstall(
        isInstalledApp: Boolean,
        packageName: String?,
        responseJson: String?,
        onUninstallConfirmed: ((String) -> Unit)? = null,
        onCancelled: (() -> Unit)? = null
    ): Boolean {
        val evaluation = shouldPromptUninstall(isInstalledApp, packageName, responseJson)
        if (evaluation !is EvaluationResult.Prompt) {
            return false
        }

        if (evaluation.analysisId.isNotEmpty()) {
            lastPromptedAnalysisId = evaluation.analysisId
        }
        lastPromptedPackage = evaluation.packageName

        showConfirmationDialog(
            packageName = evaluation.packageName,
            onUninstallConfirmed = onUninstallConfirmed ?: { pkg ->
                launchUninstallIntent(pkg)
                Unit
            },
            onCancelled = onCancelled
        )
        return true
    }

    /**
     * Displays the confirmation dialog offering UNINSTALL and CANCEL.
     */
    fun showConfirmationDialog(
        packageName: String,
        onUninstallConfirmed: (String) -> Unit,
        onCancelled: (() -> Unit)? = null
    ) {
        if (dialogLauncher != null) {
            dialogLauncher.invoke(
                packageName,
                { targetPkg ->
                    activeDialog = null
                    onUninstallConfirmed(targetPkg)
                },
                {
                    activeDialog = null
                    onCancelled?.invoke()
                }
            )
            return
        }

        val ctx = context ?: return
        if (ctx is Activity && (ctx.isFinishing || ctx.isDestroyed)) {
            return
        }

        dismissActiveDialog()

        val title = try {
            ctx.getString(R.string.critical_risk_dialog_title)
        } catch (_: Exception) {
            "Critical Security Risk Detected"
        }

        val message = try {
            ctx.getString(R.string.critical_risk_dialog_message)
        } catch (_: Exception) {
            "SpyAware has classified this application as CRITICAL risk based on the analysis findings. This may indicate potentially dangerous behaviour. Would you like to uninstall this application?"
        }

        val btnUninstall = try {
            ctx.getString(R.string.btn_uninstall)
        } catch (_: Exception) {
            "UNINSTALL"
        }

        val btnCancel = try {
            ctx.getString(R.string.btn_cancel_dialog)
        } catch (_: Exception) {
            "CANCEL"
        }

        val dialog = MaterialAlertDialogBuilder(ctx)
            .setTitle(title)
            .setMessage(message)
            .setCancelable(true)
            .setPositiveButton(btnUninstall) { _, _ ->
                activeDialog = null
                onUninstallConfirmed(packageName)
            }
            .setNegativeButton(btnCancel) { d, _ ->
                d.dismiss()
                activeDialog = null
                onCancelled?.invoke()
            }
            .setOnCancelListener {
                activeDialog = null
                onCancelled?.invoke()
            }
            .create()

        activeDialog = dialog
        dialog.show()
    }

    /**
     * Launches Android's official package uninstallation UI.
     */
    fun launchUninstallIntent(packageName: String): Boolean {
        val validation = validatePackageForUninstall(packageName)
        if (validation is ValidationResult.Invalid) {
            context?.let { Toast.makeText(it, validation.reason, Toast.LENGTH_SHORT).show() }
            return false
        }

        if (!isPackageInstalled(packageName)) {
            val msg = try {
                context?.getString(R.string.uninstall_err_not_installed, packageName)
            } catch (_: Exception) {
                null
            } ?: "Application '$packageName' is no longer installed on this device."
            context?.let { Toast.makeText(it, msg, Toast.LENGTH_LONG).show() }
            return false
        }

        val intent = createUninstallIntent(packageName)

        if (activityLauncher != null) {
            activityLauncher.invoke(intent)
            pendingUninstallPackageName = packageName
            return true
        }

        val ctx = context ?: return false
        if (ctx !is Activity) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

        return try {
            ctx.startActivity(intent)
            pendingUninstallPackageName = packageName
            true
        } catch (e: ActivityNotFoundException) {
            val msg = try {
                ctx.getString(
                    R.string.uninstall_err_cannot_launch,
                    "No system uninstaller available"
                )
            } catch (_: Exception) {
                null
            } ?: "Unable to open system uninstall confirmation screen: No package uninstaller found."
            Toast.makeText(ctx, msg, Toast.LENGTH_LONG).show()
            false
        } catch (e: Exception) {
            val msg = try {
                ctx.getString(
                    R.string.uninstall_err_cannot_launch,
                    e.localizedMessage ?: "Launch error"
                )
            } catch (_: Exception) {
                null
            } ?: "Unable to open system uninstall confirmation screen: ${e.message}"
            Toast.makeText(ctx, msg, Toast.LENGTH_LONG).show()
            false
        }
    }

    /**
     * Handles activity resumption to verify if the application was actually uninstalled.
     * Prevents false claims of uninstallation if the user cancelled system confirmation.
     */
    fun handleResume(
        onAppUninstalled: ((String) -> Unit)? = null,
        onAppStillInstalled: ((String) -> Unit)? = null
    ) {
        val pendingPkg = pendingUninstallPackageName ?: return
        pendingUninstallPackageName = null

        val stillInstalled = isPackageInstalled(pendingPkg)
        if (!stillInstalled) {
            val msg = try {
                context?.getString(R.string.msg_app_uninstalled, pendingPkg)
            } catch (_: Exception) {
                null
            } ?: "Application '$pendingPkg' was uninstalled."
            context?.let { Toast.makeText(it, msg, Toast.LENGTH_SHORT).show() }
            onAppUninstalled?.invoke(pendingPkg)
        } else {
            onAppStillInstalled?.invoke(pendingPkg)
        }
    }

    /**
     * Dismisses the active dialog safely.
     */
    fun dismissActiveDialog() {
        try {
            if (activeDialog?.isShowing == true) {
                activeDialog?.dismiss()
            }
        } catch (_: Exception) {}
        activeDialog = null
    }

    /**
     * Clears tracked prompt and pending uninstall state.
     */
    fun resetPromptState() {
        lastPromptedAnalysisId = null
        lastPromptedPackage = null
        pendingUninstallPackageName = null
    }
}
