package com.spyaware.analyzer

import android.app.Dialog
import android.content.Context
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.content.ContextCompat
import com.spyaware.analyzer.databinding.DialogSettingsBinding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SettingsDialog(
    private val context: Context,
    private val scope: CoroutineScope,
    private val preferences: BackendPreferences,
    private val onSaved: (newUrl: String) -> Unit
) {

    private val healthChecker = BackendHealthChecker()
    private var testJob: Job? = null

    fun show() {
        val binding = DialogSettingsBinding.inflate(LayoutInflater.from(context))
        val dialog = Dialog(context).apply {
            setContentView(binding.root)
            window?.setLayout(
                (context.resources.displayMetrics.widthPixels * 0.92).toInt(),
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            setCancelable(true)
        }

        binding.etBackendUrl.setText(preferences.backendUrl)

        binding.btnPresetEmulator.setOnClickListener {
            binding.etBackendUrl.setText("http://10.0.2.2:8000")
            binding.tilBackendUrl.error = null
        }

        binding.btnPresetAdb.setOnClickListener {
            binding.etBackendUrl.setText("http://localhost:8000")
            binding.tilBackendUrl.error = null
        }

        binding.btnTestConnection.setOnClickListener {
            val input = binding.etBackendUrl.text?.toString() ?: ""
            when (val validation = BackendPreferences.validate(input)) {
                is BackendPreferences.ValidationResult.Invalid -> {
                    binding.tilBackendUrl.error = validation.reason
                    binding.layoutTestResult.visibility = View.VISIBLE
                    binding.tvTestResult.setTextColor(ContextCompat.getColor(context, R.color.error_red))
                    binding.tvTestResult.text = "Validation Error: ${validation.reason}"
                }
                is BackendPreferences.ValidationResult.Valid -> {
                    binding.tilBackendUrl.error = null
                    testConnection(binding, validation.normalizedUrl)
                }
            }
        }

        binding.btnCancelSettings.setOnClickListener {
            testJob?.cancel()
            dialog.dismiss()
        }

        binding.btnSaveSettings.setOnClickListener {
            val input = binding.etBackendUrl.text?.toString() ?: ""
            when (val validation = BackendPreferences.validate(input)) {
                is BackendPreferences.ValidationResult.Invalid -> {
                    binding.tilBackendUrl.error = validation.reason
                    Toast.makeText(context, validation.reason, Toast.LENGTH_SHORT).show()
                }
                is BackendPreferences.ValidationResult.Valid -> {
                    testJob?.cancel()
                    preferences.backendUrl = validation.normalizedUrl
                    onSaved(validation.normalizedUrl)
                    dialog.dismiss()
                }
            }
        }

        dialog.show()
    }

    private fun testConnection(binding: DialogSettingsBinding, url: String) {
        testJob?.cancel()
        binding.layoutTestResult.visibility = View.VISIBLE
        binding.progressBarTest.visibility = View.VISIBLE
        binding.tvTestResult.setTextColor(ContextCompat.getColor(context, R.color.text_secondary))
        binding.tvTestResult.text = "Connecting to $url/api/health..."

        testJob = scope.launch {
            val result = healthChecker.checkHealth(url)
            withContext(Dispatchers.Main) {
                binding.progressBarTest.visibility = View.GONE
                if (result.isHealthy) {
                    binding.tvTestResult.setTextColor(ContextCompat.getColor(context, R.color.success_green))
                    binding.tvTestResult.text = "✓ SUCCESS:\n${result.message}"
                } else {
                    binding.tvTestResult.setTextColor(ContextCompat.getColor(context, R.color.error_red))
                    val help = result.troubleshootingHelp?.let { "\n\n$it" } ?: ""
                    binding.tvTestResult.text = "✗ FAILED:\n${result.message}$help"
                }
            }
        }
    }
}
