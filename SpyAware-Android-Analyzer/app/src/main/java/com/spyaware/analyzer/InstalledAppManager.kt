package com.spyaware.analyzer

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class InstalledAppManager(private val context: Context) {

    data class InstalledAppItem(
        val packageName: String,
        val appName: String,
        val versionName: String,
        val isSystem: Boolean,
        val isSplit: Boolean,
        val splitCount: Int,
        val apkSize: Long,
        val iconBase64: String? = null
    ) {
        fun toJson(): JSONObject {
            return JSONObject().apply {
                put("packageName", packageName)
                put("appName", appName)
                put("versionName", versionName)
                put("isSystem", isSystem)
                put("isSplit", isSplit)
                put("splitCount", splitCount)
                put("apkSize", apkSize)
                if (iconBase64 != null) {
                    put("icon", iconBase64)
                }
            }
        }
    }

    companion object {
        // Strict package name validation according to Android conventions
        private val PACKAGE_NAME_REGEX = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$")

        // Allowed canonical path prefixes for installed APK files
        private val ALLOWED_APK_PATH_PREFIXES = listOf(
            "/data/app",
            "/system/app",
            "/system/priv-app",
            "/system_ext",
            "/product",
            "/vendor",
            "/apex"
        )

        fun isValidPackageName(packageName: String): Boolean {
            return PACKAGE_NAME_REGEX.matches(packageName.trim())
        }

        fun isSystemApp(appInfo: ApplicationInfo): Boolean {
            val flags = appInfo.flags
            return (flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                    (flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        }

        fun isPackageInstalled(context: Context, packageName: String): Boolean {
            val trimmed = packageName.trim()
            if (!isValidPackageName(trimmed)) {
                return false
            }
            val pm = context.packageManager
            return try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(trimmed, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(trimmed, 0)
                }
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            } catch (_: Exception) {
                false
            }
        }
    }

    /**
     * Checks if a package is currently installed on the device.
     */
    fun isPackageInstalled(packageName: String): Boolean {
        return Companion.isPackageInstalled(context, packageName)
    }

    /**
     * Enumerates installed applications on device.
     * User-installed apps are returned by default. System apps included if [includeSystem] is true.
     */
    fun getInstalledApps(includeSystem: Boolean = false): List<InstalledAppItem> {
        val pm = context.packageManager
        val packages: List<PackageInfo> = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(0)
            }
        } catch (_: Exception) {
            emptyList()
        }

        val appList = ArrayList<InstalledAppItem>()

        for (pkgInfo in packages) {
            val appInfo = pkgInfo.applicationInfo ?: continue
            val isSystem = isSystemApp(appInfo)

            if (!includeSystem && isSystem) {
                continue
            }

            val packageName = pkgInfo.packageName ?: continue
            val appName = try {
                appInfo.loadLabel(pm).toString()
            } catch (_: Exception) {
                packageName
            }

            val versionName = pkgInfo.versionName ?: "1.0"

            val splitDirs = appInfo.splitPublicSourceDirs ?: appInfo.splitSourceDirs
            val isSplit = !splitDirs.isNullOrEmpty()
            val splitCount = splitDirs?.size ?: 0

            val apkPath = appInfo.publicSourceDir ?: appInfo.sourceDir
            val apkSize = if (apkPath != null) {
                try {
                    val file = File(apkPath)
                    if (file.exists() && file.isFile) file.length() else 0L
                } catch (_: Exception) {
                    0L
                }
            } else {
                0L
            }

            val iconBase64 = loadIconAsBase64(appInfo, pm)

            appList.add(
                InstalledAppItem(
                    packageName = packageName,
                    appName = appName,
                    versionName = versionName,
                    isSystem = isSystem,
                    isSplit = isSplit,
                    splitCount = splitCount,
                    apkSize = apkSize,
                    iconBase64 = iconBase64
                )
            )
        }

        // Sort alphabetically by application display name
        appList.sortBy { it.appName.lowercase() }
        return appList
    }

    /**
     * Serializes installed applications to a JSON string array.
     */
    fun getInstalledAppsJson(includeSystem: Boolean = false): String {
        val apps = getInstalledApps(includeSystem)
        val jsonArray = JSONArray()
        for (app in apps) {
            jsonArray.put(app.toJson())
        }
        return jsonArray.toString()
    }

    /**
     * Safely resolves the installed application's APK file.
     * Validates package name, existence, and permissions.
     */
    fun resolveApkFile(packageName: String): File {
        val trimmed = packageName.trim()
        if (!isValidPackageName(trimmed)) {
            throw IllegalArgumentException("Invalid package identifier format: '$packageName'")
        }

        val pm = context.packageManager
        val pkgInfo = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(trimmed, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(trimmed, 0)
            }
        } catch (e: PackageManager.NameNotFoundException) {
            throw IllegalArgumentException("Target package '$trimmed' is not installed on this device", e)
        }

        val appInfo = pkgInfo.applicationInfo
            ?: throw IllegalStateException("Application metadata not accessible for '$trimmed'")

        val rawPath = appInfo.publicSourceDir ?: appInfo.sourceDir
            ?: throw IllegalStateException("APK file path unavailable for '$trimmed'")

        val apkFile = File(rawPath)
        val canonicalPath = try {
            apkFile.canonicalPath
        } catch (e: Exception) {
            throw SecurityException("Unable to resolve canonical path for APK: ${e.message}", e)
        }

        // Validate canonical path against allowed system and app directories
        val isAllowedPath = ALLOWED_APK_PATH_PREFIXES.any { prefix ->
            canonicalPath.startsWith(prefix)
        }
        if (!isAllowedPath) {
            throw SecurityException("Resolved APK path '$canonicalPath' is outside permitted application directories.")
        }

        if (!apkFile.exists() || !apkFile.isFile) {
            throw IllegalStateException("APK file not found on disk at '$canonicalPath'")
        }

        if (!apkFile.canRead()) {
            throw SecurityException("Insufficient permissions to read APK file at '$canonicalPath'")
        }

        return apkFile
    }

    /**
     * Detects if an application is installed as a split APK package.
     */
    fun checkSplitStatus(packageName: String): Pair<Boolean, Int> {
        val trimmed = packageName.trim()
        if (!isValidPackageName(trimmed)) {
            return Pair(false, 0)
        }

        val pm = context.packageManager
        return try {
            val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(trimmed, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(trimmed, 0)
            }
            val appInfo = pkgInfo.applicationInfo
            val splits = appInfo?.splitPublicSourceDirs ?: appInfo?.splitSourceDirs
            Pair(!splits.isNullOrEmpty(), splits?.size ?: 0)
        } catch (_: Exception) {
            Pair(false, 0)
        }
    }

    /**
     * Resolves split APK names if the application is installed as a split APK package.
     */
    fun getSplitNames(packageName: String): List<String> {
        val trimmed = packageName.trim()
        if (!isValidPackageName(trimmed)) {
            return emptyList()
        }

        val pm = context.packageManager
        return try {
            val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(trimmed, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(trimmed, 0)
            }
            val appInfo = pkgInfo.applicationInfo ?: return emptyList()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && appInfo.splitNames != null) {
                appInfo.splitNames?.toList() ?: emptyList()
            } else {
                val splits = appInfo.splitPublicSourceDirs ?: appInfo.splitSourceDirs
                splits?.map { File(it).name } ?: emptyList()
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Copies APK to an app-private cache directory if isolated staging is needed.
     * Enforces storage capacity checks to prevent device storage exhaustion.
     */
    fun stageApkToCache(apkFile: File, packageName: String): File {
        val cacheDir = File(context.cacheDir, "staged_apks")
        if (!cacheDir.exists()) {
            cacheDir.mkdirs()
        }

        val requiredBytes = apkFile.length() + (10L * 1024L * 1024L) // 10MB safety margin
        if (cacheDir.usableSpace < requiredBytes) {
            val reqMb = requiredBytes / (1024 * 1024)
            val availMb = cacheDir.usableSpace / (1024 * 1024)
            throw IllegalStateException("Insufficient device storage to stage APK: requires ${reqMb}MB, available ${availMb}MB")
        }

        val sanitizedName = packageName.replace(Regex("[^a-zA-Z0-9._]"), "_")
        val stagedFile = File(cacheDir, "${sanitizedName}_staged.apk")

        apkFile.copyTo(stagedFile, overwrite = true)
        return stagedFile
    }

    /**
     * Cleans up all temporary staged APK files in the app-private cache.
     */
    fun cleanupStagedApks() {
        try {
            val cacheDir = File(context.cacheDir, "staged_apks")
            if (cacheDir.exists()) {
                cacheDir.listFiles()?.forEach { file ->
                    if (file.isFile && file.name.endsWith(".apk")) {
                        file.delete()
                    }
                }
            }
        } catch (_: Exception) {
            // Ignore cleanup errors
        }
    }

    /**
     * Converts an ApplicationInfo icon Drawable into a compressed PNG base64 string.
     */
    private fun loadIconAsBase64(appInfo: ApplicationInfo, pm: PackageManager): String? {
        return try {
            val drawable = appInfo.loadIcon(pm)
            val bitmap = drawableToBitmap(drawable, 64, 64) ?: return null
            val byteStream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.PNG, 90, byteStream)
            val bytes = byteStream.toByteArray()
            "data:image/png;base64," + Base64.encodeToString(bytes, Base64.NO_WRAP)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Safely converts any Drawable (AdaptiveIconDrawable, VectorDrawable, BitmapDrawable, etc.)
     * to a scaled Bitmap without risking crashes.
     */
    private fun drawableToBitmap(drawable: Drawable, targetWidth: Int, targetHeight: Int): Bitmap? {
        return try {
            if (drawable is BitmapDrawable && drawable.bitmap != null) {
                return Bitmap.createScaledBitmap(drawable.bitmap, targetWidth, targetHeight, true)
            }
            val width = if (drawable.intrinsicWidth > 0) drawable.intrinsicWidth else targetWidth
            val height = if (drawable.intrinsicHeight > 0) drawable.intrinsicHeight else targetHeight

            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            drawable.setBounds(0, 0, canvas.width, canvas.height)
            drawable.draw(canvas)

            if (width != targetWidth || height != targetHeight) {
                Bitmap.createScaledBitmap(bitmap, targetWidth, targetHeight, true)
            } else {
                bitmap
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Uploads the APK file to the configured FastAPI backend using multipart/form-data.
     * Streams bytes in 64 KB chunks to support large APKs without memory exhaustion.
     */
    suspend fun uploadApkToBackend(
        backendUrl: String,
        apkFile: File,
        originalFilename: String,
        dynamic: Boolean = false,
        network: Boolean = false,
        isSplit: Boolean = false,
        splitCount: Int = 0,
        splitNames: List<String>? = null,
        onProgress: (percent: Int, stage: String) -> Unit
    ): String = withContext(Dispatchers.IO) {
        val normalizedBase = BackendPreferences.normalizeUrl(backendUrl)
        val params = StringBuilder()
        if (dynamic) params.append("dynamic=true")
        if (network) {
            if (params.isNotEmpty()) params.append("&")
            params.append("network=true")
        }
        if (isSplit) {
            if (params.isNotEmpty()) params.append("&")
            params.append("is_split=true")
        }
        if (splitCount > 0) {
            if (params.isNotEmpty()) params.append("&")
            params.append("split_count=$splitCount")
        }
        if (!splitNames.isNullOrEmpty()) {
            if (params.isNotEmpty()) params.append("&")
            val rawCsv = splitNames.joinToString(",")
            val encodedCsv = java.net.URLEncoder.encode(rawCsv, "UTF-8")
            params.append("split_names=$encodedCsv")
        }
        val uploadUrl = if (params.isNotEmpty()) {
            "$normalizedBase/api/analyze?$params"
        } else {
            "$normalizedBase/api/analyze"
        }

        val boundary = "---SpyAwareBoundary" + System.currentTimeMillis()
        val lineEnd = "\r\n"
        val twoHyphens = "--"

        val totalLength = apkFile.length()
        if (totalLength <= 0) {
            throw IllegalStateException("Selected APK file is empty (0 bytes).")
        }
        if (totalLength > 150L * 1024L * 1024L) {
            val mb = totalLength / (1024 * 1024)
            throw IllegalArgumentException("Selected APK file exceeds the 150MB limit (${mb}MB). Please select an APK smaller than 150MB.")
        }

        val url = URL(uploadUrl)
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doInput = true
            doOutput = true
            useCaches = false
            connectTimeout = 15000
            readTimeout = 180000 // 3 minutes timeout for analysis execution
            setRequestProperty("Connection", "Keep-Alive")
            setRequestProperty("User-Agent", "SpyAware-Analyzer-Android/1.0")
            setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
            setRequestProperty("Accept", "application/json")
        }

        val headerPrefix = StringBuilder().apply {
            append(twoHyphens).append(boundary).append(lineEnd)
            append("Content-Disposition: form-data; name=\"file\"; filename=\"$originalFilename\"").append(lineEnd)
            append("Content-Type: application/vnd.android.package-archive").append(lineEnd)
            append(lineEnd)
        }.toString().toByteArray(Charsets.UTF_8)

        val tailSuffix = StringBuilder().apply {
            append(lineEnd)
            append(twoHyphens).append(boundary).append(twoHyphens).append(lineEnd)
        }.toString().toByteArray(Charsets.UTF_8)

        val fullContentLength = headerPrefix.size + totalLength + tailSuffix.size
        connection.setFixedLengthStreamingMode(fullContentLength)

        onProgress(5, "Connecting to backend...")

        try {
            connection.outputStream.use { out ->
                out.write(headerPrefix)
                out.flush()

                FileInputStream(apkFile).use { fis ->
                    val buffer = ByteArray(64 * 1024)
                    var bytesRead: Int
                    var totalBytesSent = 0L

                    while (fis.read(buffer).also { bytesRead = it } != -1) {
                        out.write(buffer, 0, bytesRead)
                        totalBytesSent += bytesRead

                        val uploadProgress = ((totalBytesSent * 75) / totalLength).toInt() + 5
                        val currentMb = totalBytesSent / (1024 * 1024)
                        val totalMb = totalLength / (1024 * 1024)
                        onProgress(
                            minOf(80, uploadProgress),
                            "Uploading APK (${currentMb}MB / ${totalMb}MB)..."
                        )
                    }
                }

                out.write(tailSuffix)
                out.flush()
            }

            onProgress(85, "Backend analyzing APK (static manifest, DEX bytecode & risk rules)...")

            val statusCode = connection.responseCode
            val stream = if (statusCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream ?: connection.inputStream
            }

            val responseBody = BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { it.readText() }

            if (statusCode == 200) {
                onProgress(100, "Analysis complete!")
                return@withContext responseBody
            } else {
                val errorDetail = try {
                    val json = JSONObject(responseBody)
                    json.optString("detail", "Server error ($statusCode)")
                } catch (_: Exception) {
                    "HTTP $statusCode: $responseBody"
                }
                throw IllegalStateException("Analysis backend error ($statusCode): $errorDetail")
            }
        } finally {
            connection.disconnect()
        }
    }
}
