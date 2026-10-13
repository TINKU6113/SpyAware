package com.spyaware.analyzer

import android.content.Context
import android.content.SharedPreferences
import java.net.URI

class BackendPreferences(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var backendUrl: String
        get() = prefs.getString(KEY_BACKEND_URL, DEFAULT_BACKEND_URL) ?: DEFAULT_BACKEND_URL
        set(value) {
            val normalized = normalizeUrl(value)
            prefs.edit().putString(KEY_BACKEND_URL, normalized).apply()
        }

    sealed class ValidationResult {
        data class Valid(val normalizedUrl: String) : ValidationResult()
        data class Invalid(val reason: String) : ValidationResult()
    }

    companion object {
        private const val PREFS_NAME = "spyaware_analyzer_prefs"
        private const val KEY_BACKEND_URL = "backend_url"
        const val DEFAULT_BACKEND_URL = "http://10.0.2.2:8000"

        fun normalizeUrl(rawUrl: String): String {
            return rawUrl.trim().trimEnd('/')
        }

        fun validate(rawUrl: String): ValidationResult {
            val trimmed = rawUrl.trim()
            if (trimmed.isEmpty()) {
                return ValidationResult.Invalid("Backend URL cannot be empty.")
            }

            if (!trimmed.startsWith("http://", ignoreCase = true) &&
                !trimmed.startsWith("https://", ignoreCase = true)
            ) {
                return ValidationResult.Invalid("URL must start with http:// or https://")
            }

            try {
                val uri = URI(trimmed)
                val scheme = uri.scheme?.lowercase()
                if (scheme != "http" && scheme != "https") {
                    return ValidationResult.Invalid("Unsupported scheme '$scheme'. Only http and https are supported.")
                }

                val host = uri.host
                if (host.isNullOrBlank()) {
                    return ValidationResult.Invalid("Invalid host name in URL.")
                }

                if (uri.port != -1 && (uri.port <= 0 || uri.port > 65535)) {
                    return ValidationResult.Invalid("Invalid port number: ${uri.port}.")
                }

                val normalized = normalizeUrl(trimmed)
                return ValidationResult.Valid(normalized)
            } catch (e: Exception) {
                return ValidationResult.Invalid("Malformed URL: ${e.localizedMessage ?: "Syntax error"}")
            }
        }
    }
}
