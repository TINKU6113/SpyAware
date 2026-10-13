package com.spyaware.analyzer

import android.content.Context
import android.webkit.WebResourceResponse
import androidx.webkit.WebViewAssetLoader
import java.io.InputStream

class SafeAssetPathHandler(private val context: Context) : WebViewAssetLoader.PathHandler {

    override fun handle(path: String): WebResourceResponse? {
        val cleanPath = path.substringBefore('?').substringBefore('#').trimStart('/')
        val targetPath = if (cleanPath.isEmpty()) "index.html" else cleanPath

        val candidates = listOf(
            targetPath,
            "dist/$targetPath",
            "assets/$targetPath",
            "dist/assets/$targetPath"
        )

        for (candidate in candidates) {
            try {
                val inputStream: InputStream = context.assets.open(candidate)
                val mimeType = getMimeType(candidate)
                val response = WebResourceResponse(mimeType, "UTF-8", inputStream)
                val headers = mapOf(
                    "Access-Control-Allow-Origin" to "*",
                    "Cache-Control" to "no-cache, no-store, must-revalidate"
                )
                response.responseHeaders = headers
                return response
            } catch (_: Exception) {
                // Try next candidate
            }
        }

        return null
    }

    private fun getMimeType(path: String): String {
        val lower = path.lowercase()
        return when {
            lower.endsWith(".html") || lower.endsWith(".htm") -> "text/html"
            lower.endsWith(".js") || lower.endsWith(".mjs") -> "application/javascript"
            lower.endsWith(".css") -> "text/css"
            lower.endsWith(".svg") -> "image/svg+xml"
            lower.endsWith(".png") -> "image/png"
            lower.endsWith(".jpg") || lower.endsWith(".jpeg") -> "image/jpeg"
            lower.endsWith(".webp") -> "image/webp"
            lower.endsWith(".json") -> "application/json"
            lower.endsWith(".ico") -> "image/x-icon"
            lower.endsWith(".apk") -> "application/vnd.android.package-archive"
            else -> "application/octet-stream"
        }
    }
}
