package com.spyaware.analyzer

import android.content.Context
import android.webkit.JavascriptInterface
import org.json.JSONArray
import org.json.JSONObject

class WebAppInterface(
    private val getBackendUrlProvider: () -> String,
    private val onConnectionReported: ((Boolean, String) -> Unit)? = null,
    private val installedAppManager: InstalledAppManager? = null,
    private val onStartAnalysis: ((packageName: String, dynamic: Boolean, network: Boolean) -> Unit)? = null,
    private val onCancelAnalysis: (() -> Unit)? = null,
    private val moduleLauncher: ModuleLauncher? = null,
    private val onModuleAction: ((ModuleDefinition) -> Unit)? = null,
    private val onModuleInstall: ((ModuleDefinition) -> Unit)? = null,
    private val onOpenAnalysisEngine: (() -> Unit)? = null,
    private val context: Context? = null
) {

    @JavascriptInterface
    fun isNativeWrapper(): Boolean = true

    @JavascriptInterface
    fun getBackendUrl(): String {
        return getBackendUrlProvider()
    }

    @JavascriptInterface
    fun getAppVersion(): String {
        return "1.0.0"
    }

    @JavascriptInterface
    fun reportConnectionStatus(online: Boolean, message: String) {
        onConnectionReported?.invoke(online, message)
    }

    @JavascriptInterface
    fun getInstalledApps(includeSystem: Boolean): String {
        return installedAppManager?.getInstalledAppsJson(includeSystem) ?: "[]"
    }

    @JavascriptInterface
    fun checkSplitStatus(packageName: String): String {
        val result = installedAppManager?.checkSplitStatus(packageName) ?: Pair(false, 0)
        val splitNames = installedAppManager?.getSplitNames(packageName) ?: emptyList()
        val jsonArray = JSONArray()
        splitNames.forEach { jsonArray.put(it) }
        return JSONObject().apply {
            put("isSplit", result.first)
            put("splitCount", result.second)
            put("splitNames", jsonArray)
        }.toString()
    }

    @JavascriptInterface
    fun analyzeInstalledApp(packageName: String, dynamic: Boolean, network: Boolean) {
        onStartAnalysis?.invoke(packageName, dynamic, network)
    }

    @JavascriptInterface
    fun cancelAnalysis() {
        onCancelAnalysis?.invoke()
    }

    @JavascriptInterface
    fun cleanupStagedApks() {
        installedAppManager?.cleanupStagedApks()
    }

    @JavascriptInterface
    fun getModulesJson(): String {
        val jsonArray = JSONArray()
        for (module in ModuleDefinition.ALL_MODULES) {
            val isInstalled = if (context != null && moduleLauncher != null) {
                moduleLauncher.isInstalled(context, module)
            } else {
                false
            }

            jsonArray.put(
                JSONObject().apply {
                    put("id", module.id)
                    put("displayName", module.displayName)
                    put("subtitle", module.subtitle)
                    put("packageName", module.packageName)
                    put("isInstalled", isInstalled)
                    put("description", module.description)
                    put("minSdk", module.minSdk)
                    put("targetSdk", module.targetSdk)
                }
            )
        }
        return jsonArray.toString()
    }

    @JavascriptInterface
    fun openModule(idOrPackage: String): Boolean {
        val module = ModuleDefinition.findById(idOrPackage) ?: return false
        onModuleAction?.invoke(module)
        return true
    }

    @JavascriptInterface
    fun installModule(idOrPackage: String): Boolean {
        val module = ModuleDefinition.findById(idOrPackage) ?: return false
        onModuleInstall?.invoke(module)
        return true
    }

    @JavascriptInterface
    fun openAnalysisEngine() {
        onOpenAnalysisEngine?.invoke()
    }
}
