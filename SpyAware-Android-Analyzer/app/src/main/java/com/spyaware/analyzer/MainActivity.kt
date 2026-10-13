package com.spyaware.analyzer

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.util.Base64
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.webkit.WebViewAssetLoader
import com.spyaware.analyzer.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URI
import java.net.URLEncoder

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var preferences: BackendPreferences
    private val healthChecker = BackendHealthChecker()
    private lateinit var installedAppManager: InstalledAppManager
    private val moduleLauncher = ModuleLauncher()
    private lateinit var moduleInstallManager: ModuleInstallManager
    private lateinit var uninstallHandler: CriticalRiskUninstallHandler
    private var isModulesSectionExpanded = true

    private var fileUploadCallback: ValueCallback<Array<Uri>>? = null
    private lateinit var filePickerLauncher: ActivityResultLauncher<Intent>

    private var healthCheckJob: Job? = null
    private var analysisJob: Job? = null
    private var isBackendHealthy = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        preferences = BackendPreferences(this)
        installedAppManager = InstalledAppManager(this)
        installedAppManager.cleanupStagedApks()
        moduleInstallManager = ModuleInstallManager(this)
        uninstallHandler = CriticalRiskUninstallHandler(
            context = this,
            isPackageInstalledProvider = { pkg ->
                installedAppManager.isPackageInstalled(pkg)
            }
        )

        setupFilePickerLauncher()
        setupTopBar()
        setupBackNavigation()
        setupErrorView()
        setupWebView()
        setupModulesSection()

        loadDashboard(preferences.backendUrl)
        checkBackendHealth(preferences.backendUrl)
    }

    private fun setupFilePickerLauncher() {
        filePickerLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK && result.data != null) {
                val data = result.data
                val uris = when {
                    data?.clipData != null -> {
                        val clip = data.clipData!!
                        Array(clip.itemCount) { i -> clip.getItemAt(i).uri }
                    }
                    data?.data != null -> {
                        arrayOf(data.data!!)
                    }
                    else -> null
                }
                fileUploadCallback?.onReceiveValue(uris)
            } else {
                // Critical: Chromium must be notified with null on cancel to release the file chooser
                fileUploadCallback?.onReceiveValue(null)
            }
            fileUploadCallback = null
        }
    }

    private fun setupTopBar() {
        updateBackendDisplay(preferences.backendUrl)

        binding.btnSettings.setOnClickListener {
            showSettingsDialog()
        }

        binding.btnRefresh.setOnClickListener {
            checkBackendHealth(preferences.backendUrl)
            binding.webView.reload()
        }

        binding.btnStatusChip.setOnClickListener {
            showSettingsDialog()
        }
    }

    private fun updateBackendDisplay(url: String) {
        binding.tvBackendAddress.text = url
    }

    private fun setupBackNavigation() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (binding.webView.canGoBack()) {
                    binding.webView.goBack()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })
    }

    private fun setupErrorView() {
        binding.btnRetryConnection.setOnClickListener {
            binding.layoutError.visibility = View.GONE
            binding.webView.visibility = View.VISIBLE
            checkBackendHealth(preferences.backendUrl)
            binding.webView.reload()
        }

        binding.btnConfigureBackend.setOnClickListener {
            showSettingsDialog()
        }
    }

    private fun setupWebView() {
        val safeAssetPathHandler = SafeAssetPathHandler(this)
        val assetLoader = WebViewAssetLoader.Builder()
            .setDomain("appassets.androidplatform.net")
            .addPathHandler("/assets/", safeAssetPathHandler)
            .build()

        val settings = binding.webView.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.allowFileAccess = false
        settings.allowContentAccess = false
        settings.useWideViewPort = false
        settings.loadWithOverviewMode = false
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
        settings.cacheMode = WebSettings.LOAD_DEFAULT
        settings.userAgentString = "${settings.userAgentString} SpyAwareAnalyzerApp/1.0"

        binding.webView.addJavascriptInterface(
            WebAppInterface(
                getBackendUrlProvider = { preferences.backendUrl },
                onConnectionReported = { online, _ ->
                    runOnUiThread { updateStatusBadge(online) }
                },
                installedAppManager = installedAppManager,
                onStartAnalysis = { packageName, dynamic, network ->
                    startInstalledAppAnalysis(packageName, dynamic, network)
                },
                onCancelAnalysis = {
                    cancelAnalysisJob()
                },
                moduleLauncher = moduleLauncher,
                onModuleAction = { module ->
                    runOnUiThread { handleModuleAction(module) }
                },
                onModuleInstall = { module ->
                    runOnUiThread { startModuleInstallation(module) }
                },
                onOpenAnalysisEngine = {
                    runOnUiThread { openAnalysisEngine() }
                },
                context = this
            ),
            "SpyAwareBridge"
        )

        binding.webView.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(
                view: WebView?,
                request: WebResourceRequest?
            ): WebResourceResponse? {
                val url = request?.url ?: return null
                var response = assetLoader.shouldInterceptRequest(url)
                if (response == null && url.host.equals("appassets.androidplatform.net", ignoreCase = true)) {
                    val path = url.path?.trimStart('/') ?: ""
                    if (path.isNotEmpty()) {
                        response = safeAssetPathHandler.handle(path)
                    }
                }
                return response
            }

            override fun shouldOverrideUrlLoading(
                view: WebView?,
                request: WebResourceRequest?
            ): Boolean {
                val uri = request?.url ?: return false
                val host = uri.host ?: ""

                // Allow internal asset loader origin
                if (host.equals("appassets.androidplatform.net", ignoreCase = true)) {
                    return false
                }

                // Allow configured backend origin
                try {
                    val backendUri = URI(preferences.backendUrl)
                    if (backendUri.host.equals(host, ignoreCase = true)) {
                        return false
                    }
                } catch (_: Exception) {}

                // External HTTP/HTTPS links open in external browser
                if (uri.scheme.equals("http", ignoreCase = true) || uri.scheme.equals("https", ignoreCase = true)) {
                    try {
                        val browserIntent = Intent(Intent.ACTION_VIEW, uri)
                        startActivity(browserIntent)
                    } catch (e: Exception) {
                        Toast.makeText(this@MainActivity, "Cannot open link: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                    return true
                }

                return true
            }

            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                binding.progressBar.visibility = View.VISIBLE
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                binding.progressBar.visibility = View.GONE
            }

            override fun onReceivedError(
                view: WebView?,
                request: WebResourceRequest?,
                error: WebResourceError?
            ) {
                if (request?.isForMainFrame == true) {
                    binding.progressBar.visibility = View.GONE
                    showErrorOverlay(
                        title = "Failed to load dashboard",
                        details = "WebView Error (${error?.errorCode}): ${error?.description}"
                    )
                }
            }
        }

        binding.webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                binding.progressBar.progress = newProgress
                if (newProgress >= 100) {
                    binding.progressBar.visibility = View.GONE
                } else {
                    binding.progressBar.visibility = View.VISIBLE
                }
            }

            override fun onShowFileChooser(
                webView: WebView?,
                filePathCallback: ValueCallback<Array<Uri>>?,
                fileChooserParams: FileChooserParams?
            ): Boolean {
                // Cancel existing pending callback to prevent leaks
                fileUploadCallback?.onReceiveValue(null)
                fileUploadCallback = filePathCallback

                val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                    type = "*/*"
                    addCategory(Intent.CATEGORY_OPENABLE)
                    putExtra(
                        Intent.EXTRA_MIME_TYPES,
                        arrayOf(
                            "application/vnd.android.package-archive",
                            "application/zip",
                            "application/octet-stream"
                        )
                    )
                }

                try {
                    filePickerLauncher.launch(Intent.createChooser(intent, "Select APK to Analyze"))
                    return true
                } catch (e: Exception) {
                    fileUploadCallback?.onReceiveValue(null)
                    fileUploadCallback = null
                    Toast.makeText(this@MainActivity, "No file manager available: ${e.message}", Toast.LENGTH_SHORT).show()
                    return false
                }
            }
        }
    }

    private fun startInstalledAppAnalysis(packageName: String, dynamic: Boolean, network: Boolean) {
        analysisJob?.cancel()
        analysisJob = lifecycleScope.launch {
            try {
                notifyUploadProgress(5, "Resolving installed application APK...")

                val apkFile = installedAppManager.resolveApkFile(packageName)
                val originalFilename = "${packageName}.apk"
                val splitStatus = installedAppManager.checkSplitStatus(packageName)
                val splitNames = installedAppManager.getSplitNames(packageName)

                notifyUploadProgress(10, "Connecting to configured backend...")

                val responseJson = installedAppManager.uploadApkToBackend(
                    backendUrl = preferences.backendUrl,
                    apkFile = apkFile,
                    originalFilename = originalFilename,
                    dynamic = dynamic,
                    network = network,
                    isSplit = splitStatus.first,
                    splitCount = splitStatus.second,
                    splitNames = splitNames,
                    onProgress = { percent, stage ->
                        notifyUploadProgress(percent, stage)
                    }
                )

                withContext(Dispatchers.Main) {
                    notifyAnalysisSuccess(responseJson)
                    uninstallHandler.checkAndPromptUninstall(
                        isInstalledApp = true,
                        packageName = packageName,
                        responseJson = responseJson
                    )
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    notifyAnalysisError(e.message ?: "Failed to analyze installed application")
                }
            } finally {
                installedAppManager.cleanupStagedApks()
            }
        }
    }

    private fun cancelAnalysisJob() {
        analysisJob?.cancel()
        installedAppManager.cleanupStagedApks()
        notifyAnalysisError("Analysis cancelled by user")
    }

    private fun notifyUploadProgress(percent: Int, stage: String) {
        runOnUiThread {
            val escapedStage = JSONObject.quote(stage)
            binding.webView.evaluateJavascript(
                "try { window.onNativeUploadProgress?.({ percent: $percent, stage: $escapedStage }); } catch(e){}",
                null
            )
        }
    }

    private fun notifyAnalysisSuccess(jsonResponse: String) {
        runOnUiThread {
            try {
                val b64 = Base64.encodeToString(
                    jsonResponse.toByteArray(Charsets.UTF_8),
                    Base64.NO_WRAP
                )
                val script = """
                    try {
                        const bin = atob('$b64');
                        const bytes = new Uint8Array(bin.length);
                        for (let i = 0; i < bin.length; i++) {
                            bytes[i] = bin.charCodeAt(i);
                        }
                        const jsonStr = new TextDecoder('utf-8').decode(bytes);
                        const report = JSON.parse(jsonStr);
                        if (window.onNativeAnalysisSuccess) {
                            window.onNativeAnalysisSuccess(report);
                        } else {
                            console.error('window.onNativeAnalysisSuccess is not defined');
                        }
                    } catch(err) {
                        console.error('Failed to parse native analysis report:', err);
                        if (window.onNativeAnalysisError) {
                            window.onNativeAnalysisError('Failed to parse analysis report: ' + err.message);
                        }
                    }
                """.trimIndent()
                binding.webView.evaluateJavascript(script, null)
            } catch (e: Exception) {
                notifyAnalysisError("Failed to deliver analysis report: " + (e.message ?: "Bridge error"))
            }
        }
    }

    private fun notifyAnalysisError(errorMessage: String) {
        runOnUiThread {
            val escaped = JSONObject.quote(errorMessage)
            binding.webView.evaluateJavascript(
                "try { window.onNativeAnalysisError?.($escaped); } catch(e){}",
                null
            )
        }
    }

    private fun loadDashboard(backendUrl: String) {
        val encodedBackend = try {
            URLEncoder.encode(backendUrl, "UTF-8")
        } catch (_: Exception) {
            backendUrl
        }
        val targetUrl = "https://appassets.androidplatform.net/assets/index.html?backend=$encodedBackend"
        binding.webView.loadUrl(targetUrl)
    }

    private fun checkBackendHealth(backendUrl: String) {
        healthCheckJob?.cancel()
        setCheckingStatus()

        healthCheckJob = lifecycleScope.launch {
            val result = healthChecker.checkHealth(backendUrl)
            isBackendHealthy = result.isHealthy
            updateStatusBadge(result.isHealthy)

            if (!result.isHealthy) {
                binding.tvErrorDetails.text = result.message
                if (result.troubleshootingHelp != null) {
                    binding.tvErrorTroubleshooting.text = result.troubleshootingHelp
                }
            }
        }
    }

    private fun setCheckingStatus() {
        binding.tvStatusText.text = getString(R.string.status_checking)
        binding.tvStatusText.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
        binding.viewStatusDot.backgroundTintList = ContextCompat.getColorStateList(this, R.color.warning_amber)

        binding.tvAnalysisEngineStatus.text = "Checking..."
        binding.tvAnalysisEngineStatus.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
        binding.dotAnalysisEngineStatus.backgroundTintList = ContextCompat.getColorStateList(this, R.color.warning_amber)
    }

    private fun updateStatusBadge(online: Boolean) {
        if (online) {
            binding.tvStatusText.text = getString(R.string.status_online)
            binding.tvStatusText.setTextColor(ContextCompat.getColor(this, R.color.success_green))
            binding.viewStatusDot.backgroundTintList = ContextCompat.getColorStateList(this, R.color.success_green)
            binding.layoutError.visibility = View.GONE
            binding.webView.visibility = View.VISIBLE

            binding.tvAnalysisEngineStatus.text = "Available"
            binding.tvAnalysisEngineStatus.setTextColor(ContextCompat.getColor(this, R.color.success_green))
            binding.dotAnalysisEngineStatus.backgroundTintList = ContextCompat.getColorStateList(this, R.color.success_green)
        } else {
            binding.tvStatusText.text = getString(R.string.status_offline)
            binding.tvStatusText.setTextColor(ContextCompat.getColor(this, R.color.error_red))
            binding.viewStatusDot.backgroundTintList = ContextCompat.getColorStateList(this, R.color.error_red)

            binding.tvAnalysisEngineStatus.text = "Offline"
            binding.tvAnalysisEngineStatus.setTextColor(ContextCompat.getColor(this, R.color.error_red))
            binding.dotAnalysisEngineStatus.backgroundTintList = ContextCompat.getColorStateList(this, R.color.error_red)
        }
    }

    private fun showErrorOverlay(title: String, details: String) {
        binding.webView.visibility = View.GONE
        binding.layoutError.visibility = View.VISIBLE
        binding.tvErrorTitle.text = title
        binding.tvErrorDetails.text = details
    }

    private fun showSettingsDialog() {
        SettingsDialog(
            context = this,
            scope = lifecycleScope,
            preferences = preferences,
            onSaved = { newUrl ->
                updateBackendDisplay(newUrl)
                checkBackendHealth(newUrl)
                loadDashboard(newUrl)
                val escapedUrl = newUrl.replace("'", "\\'")
                binding.webView.evaluateJavascript(
                    "try { window.__SPYAWARE_API_BASE__ = '$escapedUrl'; localStorage.setItem('spyaware_backend_url', '$escapedUrl'); } catch(e){}",
                    null
                )
                Toast.makeText(this, "Backend updated: $newUrl", Toast.LENGTH_SHORT).show()
            }
        ).show()
    }

    private fun setupModulesSection() {
        binding.btnToggleModules.setOnClickListener {
            toggleModulesSection()
        }

        binding.cardAnalysisEngine.setOnClickListener {
            openAnalysisEngine()
        }
        binding.btnAnalysisEngineAction.setOnClickListener {
            openAnalysisEngine()
        }

        binding.cardModule4.setOnClickListener {
            handleModuleAction(ModuleDefinition.MODULE_4)
        }
        binding.btnModule4Action.setOnClickListener {
            handleModuleAction(ModuleDefinition.MODULE_4)
        }

        binding.cardModule5.setOnClickListener {
            handleModuleAction(ModuleDefinition.MODULE_5)
        }
        binding.btnModule5Action.setOnClickListener {
            handleModuleAction(ModuleDefinition.MODULE_5)
        }

        refreshModuleStates()
    }

    fun openAnalysisEngine() {
        if (binding.layoutError.visibility == View.VISIBLE) {
            binding.layoutError.visibility = View.GONE
            binding.webView.visibility = View.VISIBLE
            checkBackendHealth(preferences.backendUrl)
            binding.webView.reload()
        }

        binding.webView.evaluateJavascript(
            """
            try {
                const el = document.getElementById('analyzer-upload-panel') ||
                           document.querySelector('[data-section="analyzer"]') ||
                           document.querySelector('main');
                if (el) {
                    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            } catch(e) {}
            """.trimIndent(),
            null
        )

        if (!isBackendHealthy) {
            Toast.makeText(
                this,
                "Backend server is offline. Please configure backend or retry.",
                Toast.LENGTH_SHORT
            ).show()
        } else {
            Toast.makeText(this, "Opening Analysis Engine...", Toast.LENGTH_SHORT).show()
        }
    }

    private fun toggleModulesSection() {
        isModulesSectionExpanded = !isModulesSectionExpanded
        if (isModulesSectionExpanded) {
            binding.layoutModulesCardsContainer.visibility = View.VISIBLE
            binding.ivModulesChevron.setImageResource(R.drawable.ic_chevron_down)
        } else {
            binding.layoutModulesCardsContainer.visibility = View.GONE
            binding.ivModulesChevron.setImageResource(R.drawable.ic_chevron_up)
        }
    }

    private fun refreshModuleStates() {
        if (isBackendHealthy) {
            binding.tvAnalysisEngineStatus.text = "Available"
            binding.tvAnalysisEngineStatus.setTextColor(ContextCompat.getColor(this, R.color.success_green))
            binding.dotAnalysisEngineStatus.backgroundTintList = ContextCompat.getColorStateList(this, R.color.success_green)
        } else {
            binding.tvAnalysisEngineStatus.text = "Offline"
            binding.tvAnalysisEngineStatus.setTextColor(ContextCompat.getColor(this, R.color.error_red))
            binding.dotAnalysisEngineStatus.backgroundTintList = ContextCompat.getColorStateList(this, R.color.error_red)
        }

        val isMod4Installed = moduleLauncher.isInstalled(this, ModuleDefinition.MODULE_4)
        if (isMod4Installed) {
            binding.tvModule4Status.text = "Installed"
            binding.tvModule4Status.setTextColor(ContextCompat.getColor(this, R.color.success_green))
            binding.dotModule4Status.backgroundTintList = ContextCompat.getColorStateList(this, R.color.success_green)
            binding.btnModule4Action.text = "OPEN MODULE"
        } else {
            binding.tvModule4Status.text = "Not Installed"
            binding.tvModule4Status.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            binding.dotModule4Status.backgroundTintList = ContextCompat.getColorStateList(this, R.color.warning_amber)
            binding.btnModule4Action.text = "OPEN MODULE"
        }

        val isMod5Installed = moduleLauncher.isInstalled(this, ModuleDefinition.MODULE_5)
        if (isMod5Installed) {
            binding.tvModule5Status.text = "Installed"
            binding.tvModule5Status.setTextColor(ContextCompat.getColor(this, R.color.success_green))
            binding.dotModule5Status.backgroundTintList = ContextCompat.getColorStateList(this, R.color.success_green)
            binding.btnModule5Action.text = "OPEN MODULE"
        } else {
            binding.tvModule5Status.text = "Not Installed"
            binding.tvModule5Status.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            binding.dotModule5Status.backgroundTintList = ContextCompat.getColorStateList(this, R.color.warning_amber)
            binding.btnModule5Action.text = "OPEN MODULE"
        }

        val installedCount = (if (isMod4Installed) 1 else 0) + (if (isMod5Installed) 1 else 0)
        binding.tvModulesHeaderSummary.text = if (installedCount > 0) {
            "$installedCount of 2 Installed"
        } else {
            "2 Modules Available"
        }
    }

    fun handleModuleAction(module: ModuleDefinition) {
        if (moduleLauncher.isInstalled(this, module)) {
            when (val result = moduleLauncher.launchModule(this, module)) {
                is ModuleLauncher.LaunchResult.Success -> {
                    Toast.makeText(this, "Opening ${module.displayName}...", Toast.LENGTH_SHORT).show()
                }
                is ModuleLauncher.LaunchResult.NoLaunchActivity -> {
                    ModuleDialogHelper.showInfoDialog(
                        this,
                        "Cannot Launch Module",
                        "Application package '${module.packageName}' is installed on this device, but does not provide a launchable main activity."
                    )
                }
                is ModuleLauncher.LaunchResult.NotInstalled -> {
                    promptInstallModule(module)
                }
                is ModuleLauncher.LaunchResult.Error -> {
                    ModuleDialogHelper.showErrorWithRetryDialog(
                        context = this,
                        title = "Launch Failed",
                        message = "Failed to launch ${module.displayName}: ${result.message}",
                        onRetryClicked = { handleModuleAction(module) }
                    )
                }
            }
        } else {
            promptInstallModule(module)
        }
    }

    private fun promptInstallModule(module: ModuleDefinition) {
        ModuleDialogHelper.showNotInstalledDialog(
            context = this,
            module = module,
            onInstallClicked = {
                startModuleInstallation(module)
            }
        )
    }

    fun startModuleInstallation(module: ModuleDefinition) {
        if (moduleLauncher.isInstalled(this, module)) {
            handleModuleAction(module)
            return
        }

        lifecycleScope.launch {
            Toast.makeText(this@MainActivity, "Preparing ${module.displayName}...", Toast.LENGTH_SHORT).show()
            when (val prepResult = moduleInstallManager.prepareInstallation(module)) {
                is ModuleInstallManager.InstallPreparationResult.Ready -> {
                    try {
                        Toast.makeText(
                            this@MainActivity,
                            "Opening installer for ${module.displayName}. Please confirm installation.",
                            Toast.LENGTH_LONG
                        ).show()
                        startActivity(prepResult.installIntent)
                    } catch (e: Exception) {
                        ModuleDialogHelper.showErrorWithRetryDialog(
                            context = this@MainActivity,
                            title = "Installation Launch Failed",
                            message = "Could not launch package installer: ${e.localizedMessage ?: e.javaClass.simpleName}",
                            onRetryClicked = { startModuleInstallation(module) }
                        )
                    }
                }
                is ModuleInstallManager.InstallPreparationResult.PermissionRequired -> {
                    ModuleDialogHelper.showPermissionRequiredDialog(
                        context = this@MainActivity,
                        module = module,
                        onOpenSettingsClicked = {
                            try {
                                startActivity(prepResult.settingsIntent)
                            } catch (e: Exception) {
                                Toast.makeText(
                                    this@MainActivity,
                                    "Could not open settings: ${e.message}",
                                    Toast.LENGTH_SHORT
                                ).show()
                            }
                        }
                    )
                }
                is ModuleInstallManager.InstallPreparationResult.AlreadyInstalled -> {
                    handleModuleAction(module)
                }
                is ModuleInstallManager.InstallPreparationResult.SignatureMismatch -> {
                    ModuleDialogHelper.showSignatureMismatchDialog(
                        context = this@MainActivity,
                        module = module,
                        details = prepResult.message
                    )
                }
                is ModuleInstallManager.InstallPreparationResult.VersionIncompatible -> {
                    ModuleDialogHelper.showVersionIncompatibleDialog(
                        context = this@MainActivity,
                        module = module,
                        details = prepResult.message
                    )
                }
                is ModuleInstallManager.InstallPreparationResult.Error -> {
                    ModuleDialogHelper.showErrorWithRetryDialog(
                        context = this@MainActivity,
                        title = "Installation Error",
                        message = prepResult.message,
                        onRetryClicked = { startModuleInstallation(module) }
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        binding.webView.onResume()
        checkBackendHealth(preferences.backendUrl)
        refreshModuleStates()
        if (::uninstallHandler.isInitialized) {
            uninstallHandler.handleResume(
                onAppUninstalled = {
                    refreshInstalledAppsInDashboard()
                }
            )
        }
    }

    private fun refreshInstalledAppsInDashboard() {
        binding.webView.evaluateJavascript(
            """
            try {
                const btn = document.querySelector('button[title*="Refresh installed apps"]');
                if (btn) {
                    btn.click();
                }
            } catch(e) {}
            """.trimIndent(),
            null
        )
    }

    override fun onPause() {
        super.onPause()
        binding.webView.onPause()
        healthCheckJob?.cancel()
        analysisJob?.cancel()
    }

    override fun onDestroy() {
        if (::uninstallHandler.isInitialized) {
            uninstallHandler.dismissActiveDialog()
        }
        binding.webView.destroy()
        healthCheckJob?.cancel()
        analysisJob?.cancel()
        installedAppManager.cleanupStagedApks()
        moduleInstallManager.cleanupStagedApks()
        super.onDestroy()
    }
}
