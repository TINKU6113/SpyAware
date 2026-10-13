package com.spyaware.analyzer

import android.content.Context
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/**
 * Helper to display consistent Material 3 dialogs for module installation,
 * launch flows, permissions, signature warnings, and error recovery.
 */
object ModuleDialogHelper {

    /**
     * Shows dialog when module is not installed (Case B).
     */
    fun showNotInstalledDialog(
        context: Context,
        module: ModuleDefinition,
        onInstallClicked: () -> Unit,
        onCancelClicked: (() -> Unit)? = null
    ) {
        MaterialAlertDialogBuilder(context)
            .setTitle("${module.displayName} is not installed.")
            .setMessage("This module provides ${module.subtitle.lowercase()}.\n\nWould you like to install it now?")
            .setPositiveButton("INSTALL MODULE") { _, _ ->
                onInstallClicked()
            }
            .setNegativeButton("CANCEL") { dialog, _ ->
                dialog.dismiss()
                onCancelClicked?.invoke()
            }
            .show()
    }

    /**
     * Shows dialog requesting authorization for "Install unknown apps".
     */
    fun showPermissionRequiredDialog(
        context: Context,
        module: ModuleDefinition,
        onOpenSettingsClicked: () -> Unit,
        onCancelClicked: (() -> Unit)? = null
    ) {
        MaterialAlertDialogBuilder(context)
            .setTitle("Install Permission Required")
            .setMessage(
                "Android requires authorization to install applications from SpyAware Analyzer.\n\n" +
                        "Please tap 'Open Settings' to enable 'Install unknown apps' for SpyAware Analyzer, then return to complete the installation of ${module.displayName}."
            )
            .setPositiveButton("OPEN SETTINGS") { _, _ ->
                onOpenSettingsClicked()
            }
            .setNegativeButton("CANCEL") { dialog, _ ->
                dialog.dismiss()
                onCancelClicked?.invoke()
            }
            .show()
    }

    /**
     * Shows dialog when existing package signature does not match the APK.
     */
    fun showSignatureMismatchDialog(
        context: Context,
        module: ModuleDefinition,
        details: String
    ) {
        MaterialAlertDialogBuilder(context)
            .setTitle("Signature Mismatch Detected")
            .setMessage(
                "$details\n\n" +
                        "Note: SpyAware Analyzer will never automatically uninstall an existing application or delete application data."
            )
            .setPositiveButton("OK") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    /**
     * Shows dialog when version downgrade protection prevents installation.
     */
    fun showVersionIncompatibleDialog(
        context: Context,
        module: ModuleDefinition,
        details: String
    ) {
        MaterialAlertDialogBuilder(context)
            .setTitle("Incompatible Version")
            .setMessage(
                "$details\n\n" +
                        "Android does not permit downgrading over an existing newer version."
            )
            .setPositiveButton("OK") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }

    /**
     * Shows dialog when installation or launch fails with retry option (Case C).
     */
    fun showErrorWithRetryDialog(
        context: Context,
        title: String,
        message: String,
        onRetryClicked: () -> Unit,
        onCancelClicked: (() -> Unit)? = null
    ) {
        MaterialAlertDialogBuilder(context)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("RETRY") { _, _ ->
                onRetryClicked()
            }
            .setNegativeButton("CANCEL") { dialog, _ ->
                dialog.dismiss()
                onCancelClicked?.invoke()
            }
            .show()
    }

    /**
     * Shows generic informative dialog.
     */
    fun showInfoDialog(
        context: Context,
        title: String,
        message: String
    ) {
        MaterialAlertDialogBuilder(context)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton("OK") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
}
