package com.spyaware.analyzer

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * Handles package presence detection and launch-intent resolution for external SpyAware modules.
 */
class ModuleLauncher {

    sealed class LaunchResult {
        object Success : LaunchResult()
        object NotInstalled : LaunchResult()
        data class NoLaunchActivity(val packageName: String) : LaunchResult()
        data class Error(val message: String, val cause: Throwable? = null) : LaunchResult()
    }

    /**
     * Checks if the external module application is currently installed.
     */
    fun isInstalled(context: Context, module: ModuleDefinition): Boolean {
        return getInstalledPackageInfo(context, module) != null
    }

    /**
     * Retrieves PackageInfo for an installed module, or null if not installed.
     */
    fun getInstalledPackageInfo(context: Context, module: ModuleDefinition): PackageInfo? {
        val pm = context.packageManager
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(module.packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(module.packageName, 0)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Resolves the launch intent for an installed module using PackageManager.
     * Configures flags to bring an existing task to the foreground if running.
     */
    fun getLaunchIntent(context: Context, module: ModuleDefinition): Intent? {
        val pm = context.packageManager
        val launchIntent = pm.getLaunchIntentForPackage(module.packageName) ?: return null
        launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
        return launchIntent
    }

    /**
     * Launches the module application if installed.
     * Handles missing package, missing launch activity, and runtime launch errors gracefully.
     */
    fun launchModule(context: Context, module: ModuleDefinition): LaunchResult {
        if (!isInstalled(context, module)) {
            return LaunchResult.NotInstalled
        }

        val launchIntent = getLaunchIntent(context, module)
            ?: return LaunchResult.NoLaunchActivity(module.packageName)

        return try {
            context.startActivity(launchIntent)
            LaunchResult.Success
        } catch (e: Exception) {
            LaunchResult.Error(
                message = e.localizedMessage ?: "Failed to launch application for ${module.displayName}",
                cause = e
            )
        }
    }
}
