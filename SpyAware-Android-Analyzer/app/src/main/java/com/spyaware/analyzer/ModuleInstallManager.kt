package com.spyaware.analyzer

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest

/**
 * Manages staging, signature verification, permission verification, and installation
 * intent generation for external SpyAware modules.
 */
class ModuleInstallManager(private val context: Context) {

    sealed class InstallPreparationResult {
        data class Ready(
            val installIntent: Intent,
            val contentUri: Uri,
            val apkFile: File
        ) : InstallPreparationResult()

        data class PermissionRequired(
            val settingsIntent: Intent
        ) : InstallPreparationResult()

        data class AlreadyInstalled(
            val packageName: String,
            val launchIntent: Intent?
        ) : InstallPreparationResult()

        data class SignatureMismatch(
            val packageName: String,
            val installedSignatures: List<String>,
            val archiveSignatures: List<String>,
            val message: String
        ) : InstallPreparationResult()

        data class VersionIncompatible(
            val packageName: String,
            val installedVersionCode: Long,
            val archiveVersionCode: Long,
            val message: String
        ) : InstallPreparationResult()

        data class Error(
            val message: String,
            val cause: Throwable? = null
        ) : InstallPreparationResult()
    }

    companion object {
        private const val MODULES_SUBDIR = "modules"
        private const val BUFFER_SIZE = 64 * 1024
        private const val MIN_STORAGE_MARGIN_BYTES = 15L * 1024L * 1024L // 15 MB margin

        // Optional local directory fallback for development environments
        private val DEV_FALLBACK_DIRS = listOf(
            File("/home/j3st3r/Desktop/SpyAware-Modules")
        )

        /**
         * Extracts SHA-256 certificate fingerprints from a PackageInfo object.
         */
        fun getCertificateFingerprints(packageInfo: PackageInfo): List<String> {
            val certs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signingInfo = packageInfo.signingInfo ?: return emptyList()
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            } ?: return emptyList()

            return certs.mapNotNull { cert ->
                try {
                    val md = MessageDigest.getInstance("SHA-256")
                    val digest = md.digest(cert.toByteArray())
                    digest.joinToString("") { "%02x".format(it) }
                } catch (_: Exception) {
                    null
                }
            }
        }
    }

    /**
     * Checks if the app is allowed to request package installs on Android 8.0+ (API 26+).
     */
    fun canRequestPackageInstalls(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.packageManager.canRequestPackageInstalls()
        } else {
            true
        }
    }

    /**
     * Creates an intent directing the user to the "Install unknown apps" settings screen.
     */
    fun createUnknownAppsSettingsIntent(): Intent {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${context.packageName}")
            )
        } else {
            Intent(Settings.ACTION_SECURITY_SETTINGS)
        }
    }

    /**
     * Prepares a module APK for installation:
     * 1. Extracts/stages APK file to app cache.
     * 2. Validates package archive integrity and metadata.
     * 3. Verifies signature compatibility against existing installations.
     * 4. Checks permission to request package installs.
     * 5. Builds FileProvider content URI and installation Intent.
     */
    suspend fun prepareInstallation(module: ModuleDefinition): InstallPreparationResult =
        withContext(Dispatchers.IO) {
            try {
                // 1. Stage the APK file from assets or fallback
                val stagedApk = stageApk(module)

                // 2. Read archive PackageInfo
                val archiveFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    PackageManager.GET_SIGNING_CERTIFICATES
                } else {
                    @Suppress("DEPRECATION")
                    PackageManager.GET_SIGNATURES
                }

                val archiveInfo = context.packageManager.getPackageArchiveInfo(
                    stagedApk.absolutePath,
                    archiveFlags
                ) ?: return@withContext InstallPreparationResult.Error(
                    "Unable to parse APK metadata from '${module.assetFileName}'. The APK package may be damaged or invalid."
                )

                // Validate package name
                if (archiveInfo.packageName != module.packageName) {
                    return@withContext InstallPreparationResult.Error(
                        "Package ID mismatch in APK: expected '${module.packageName}', but found '${archiveInfo.packageName}'."
                    )
                }

                // 3. Inspect existing installation for signature and version compatibility
                val installedInfo = getInstalledPackageInfo(module.packageName)
                if (installedInfo != null) {
                    // Check signature compatibility
                    val installedCerts = getCertificateFingerprints(installedInfo)
                    val archiveCerts = getCertificateFingerprints(archiveInfo)

                    if (installedCerts.isNotEmpty() && archiveCerts.isNotEmpty()) {
                        val signaturesOverlap = installedCerts.any { installed ->
                            archiveCerts.any { archive -> installed.equals(archive, ignoreCase = true) }
                        }

                        if (!signaturesOverlap) {
                            return@withContext InstallPreparationResult.SignatureMismatch(
                                packageName = module.packageName,
                                installedSignatures = installedCerts,
                                archiveSignatures = archiveCerts,
                                message = "The existing installation of '${module.displayName}' was signed with a different certificate than this APK. Android will reject the installation to protect application data. Automatic uninstall or overwrite is prevented."
                            )
                        }
                    }

                    // Check version code downgrade protection
                    val installedVersion = getVersionCode(installedInfo)
                    val archiveVersion = getVersionCode(archiveInfo)
                    if (installedVersion > archiveVersion) {
                        return@withContext InstallPreparationResult.VersionIncompatible(
                            packageName = module.packageName,
                            installedVersionCode = installedVersion,
                            archiveVersionCode = archiveVersion,
                            message = "The installed version ($installedVersion) is newer than the APK version ($archiveVersion). Android does not support downgrades without data loss."
                        )
                    }
                }

                // 4. Check unknown app sources permission
                if (!canRequestPackageInstalls()) {
                    return@withContext InstallPreparationResult.PermissionRequired(
                        settingsIntent = createUnknownAppsSettingsIntent()
                    )
                }

                // 5. Generate FileProvider content URI and Install Intent
                val contentUri = FileProvider.getUriForFile(
                    context,
                    "${context.packageName}.fileprovider",
                    stagedApk
                )

                val installIntent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(contentUri, "application/vnd.android.package-archive")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }

                InstallPreparationResult.Ready(
                    installIntent = installIntent,
                    contentUri = contentUri,
                    apkFile = stagedApk
                )
            } catch (e: Exception) {
                InstallPreparationResult.Error(
                    message = e.localizedMessage ?: "Failed to prepare module installation",
                    cause = e
                )
            }
        }

    /**
     * Stages the APK from assets (or development fallback) into the cache directory.
     */
    fun stageApk(module: ModuleDefinition): File {
        val modulesDir = File(context.cacheDir, MODULES_SUBDIR)
        if (!modulesDir.exists()) {
            modulesDir.mkdirs()
        }

        val targetFile = File(modulesDir, module.assetFileName)

        // Open input stream from assets, or fallback to dev folder
        val (inputStream, sourceLength) = openApkStream(module)

        inputStream.use { input ->
            // Check disk space
            val requiredSpace = sourceLength + MIN_STORAGE_MARGIN_BYTES
            if (modulesDir.usableSpace < requiredSpace) {
                val reqMb = requiredSpace / (1024 * 1024)
                val availMb = modulesDir.usableSpace / (1024 * 1024)
                throw IllegalStateException("Insufficient disk space to unpack module APK: requires ${reqMb}MB, available ${availMb}MB")
            }

            // Write to temporary file first then rename to ensure atomicity
            val tempFile = File(modulesDir, "${module.assetFileName}.tmp")
            FileOutputStream(tempFile).use { output ->
                val buffer = ByteArray(BUFFER_SIZE)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    output.write(buffer, 0, bytesRead)
                }
                output.flush()
            }

            if (targetFile.exists()) {
                targetFile.delete()
            }
            if (!tempFile.renameTo(targetFile)) {
                // If rename fails (e.g. cross-filesystem), fallback to copy
                tempFile.copyTo(targetFile, overwrite = true)
                tempFile.delete()
            }
        }

        return targetFile
    }

    private fun openApkStream(module: ModuleDefinition): Pair<InputStream, Long> {
        val assetPath = "modules/${module.assetFileName}"

        // Try opening from packaged assets first
        try {
            val fd = context.assets.openFd(assetPath)
            val length = fd.length
            val stream = fd.createInputStream()
            return Pair(stream, length)
        } catch (_: Exception) {
            // openFd may fail for compressed assets; try open directly
            try {
                val stream = context.assets.open(assetPath)
                val available = stream.available().toLong()
                return Pair(stream, if (available > 0) available else 10L * 1024L * 1024L)
            } catch (_: Exception) {
                // Try dev fallbacks
                for (dir in DEV_FALLBACK_DIRS) {
                    val file = File(dir, module.assetFileName)
                    if (file.exists() && file.isFile && file.canRead()) {
                        return Pair(file.inputStream(), file.length())
                    }
                }
                throw IllegalStateException(
                    "Module APK '${module.assetFileName}' was not found in application assets or controlled locations."
                )
            }
        }
    }

    private fun getInstalledPackageInfo(packageName: String): PackageInfo? {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, flags)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun getVersionCode(packageInfo: PackageInfo): Long {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            packageInfo.versionCode.toLong()
        }
    }

    /**
     * Cleans up staged module APKs in the cache directory.
     */
    fun cleanupStagedApks() {
        try {
            val dir = File(context.cacheDir, MODULES_SUBDIR)
            if (dir.exists()) {
                dir.listFiles()?.forEach { file ->
                    if (file.name.endsWith(".apk") || file.name.endsWith(".tmp")) {
                        file.delete()
                    }
                }
            }
        } catch (_: Exception) {
            // Ignore cleanup errors
        }
    }
}
