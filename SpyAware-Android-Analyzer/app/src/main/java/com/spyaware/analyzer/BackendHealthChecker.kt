package com.spyaware.analyzer

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException

class BackendHealthChecker {

    data class HealthCheckResult(
        val isHealthy: Boolean,
        val statusCode: Int = 0,
        val service: String? = null,
        val version: String? = null,
        val modulesSummary: String? = null,
        val message: String,
        val troubleshootingHelp: String? = null,
        val rawJson: String? = null
    )

    suspend fun checkHealth(backendUrl: String): HealthCheckResult = withContext(Dispatchers.IO) {
        val normalized = BackendPreferences.normalizeUrl(backendUrl)
        val healthUrl = "$normalized/api/health"

        var connection: HttpURLConnection? = null
        try {
            val url = URL(healthUrl)
            connection = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 5000
                readTimeout = 5000
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "SpyAware-Analyzer-Android/1.0")
            }

            val statusCode = connection.responseCode
            val stream = if (statusCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream ?: connection.inputStream
            }

            val responseBody = BufferedReader(InputStreamReader(stream)).use { it.readText() }

            if (statusCode == 200) {
                try {
                    val json = JSONObject(responseBody)
                    val status = json.optString("status")
                    val service = json.optString("service")
                    val version = json.optString("version", "1.0.0")

                    if (status.equals("healthy", ignoreCase = true) &&
                        service.contains("SpyAware", ignoreCase = true)
                    ) {
                        val modulesObj = json.optJSONObject("modules")
                        val staticMod = modulesObj?.optString("static", "UNKNOWN") ?: "UNKNOWN"
                        val dynamicMod = modulesObj?.optString("dynamic", "UNKNOWN") ?: "UNKNOWN"
                        val networkMod = modulesObj?.optString("network", "UNKNOWN") ?: "UNKNOWN"

                        val summary = "Static: $staticMod | Dynamic: $dynamicMod | Network: $networkMod"

                        return@withContext HealthCheckResult(
                            isHealthy = true,
                            statusCode = statusCode,
                            service = service,
                            version = version,
                            modulesSummary = summary,
                            message = "Connected to $service v$version ($summary)",
                            rawJson = responseBody
                        )
                    } else {
                        return@withContext HealthCheckResult(
                            isHealthy = false,
                            statusCode = statusCode,
                            message = "Connected to server, but unexpected service identity: status='$status', service='$service'.",
                            troubleshootingHelp = "Expected SpyAware-Analyzer backend at $healthUrl.",
                            rawJson = responseBody
                        )
                    }
                } catch (e: Exception) {
                    return@withContext HealthCheckResult(
                        isHealthy = false,
                        statusCode = statusCode,
                        message = "HTTP 200 received but response was not valid JSON.",
                        troubleshootingHelp = "Ensure the server at $normalized is the SpyAware-Analyzer FastAPI backend.",
                        rawJson = responseBody
                    )
                }
            } else {
                return@withContext HealthCheckResult(
                    isHealthy = false,
                    statusCode = statusCode,
                    message = "Server returned HTTP status code $statusCode.",
                    troubleshootingHelp = "Verify endpoint /api/health is accessible on the FastAPI backend."
                )
            }
        } catch (e: ConnectException) {
            return@withContext HealthCheckResult(
                isHealthy = false,
                message = "Connection refused at $normalized: ${e.message}",
                troubleshootingHelp = "• If using Android Emulator: use http://10.0.2.2:8000\n" +
                        "• If using USB physical device: run 'adb reverse tcp:8000 tcp:8000' and use http://localhost:8000\n" +
                        "• If using LAN Wi-Fi: use Ubuntu host LAN IP (e.g., http://192.168.x.x:8000)\n" +
                        "• Ensure FastAPI backend is running: 'uvicorn backend.main:app --host 0.0.0.0 --port 8000'"
            )
        } catch (e: UnknownHostException) {
            return@withContext HealthCheckResult(
                isHealthy = false,
                message = "Unknown host: ${e.message}",
                troubleshootingHelp = "Check the server IP or hostname. 'localhost' on Android refers to the Android device, not your Ubuntu host."
            )
        } catch (e: SocketTimeoutException) {
            return@withContext HealthCheckResult(
                isHealthy = false,
                message = "Connection timed out after 5 seconds.",
                troubleshootingHelp = "Server did not respond in time. Check firewall settings on the Ubuntu host and confirm port 8000 is open."
            )
        } catch (e: Exception) {
            return@withContext HealthCheckResult(
                isHealthy = false,
                message = "Connection error: ${e.localizedMessage ?: e.javaClass.simpleName}",
                troubleshootingHelp = "Verify backend is running and network configuration permits HTTP traffic."
            )
        } finally {
            connection?.disconnect()
        }
    }
}
