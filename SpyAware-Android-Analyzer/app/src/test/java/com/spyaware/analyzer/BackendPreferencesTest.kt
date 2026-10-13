package com.spyaware.analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BackendPreferencesTest {

    @Test
    fun testValidHttpUrl() {
        val result = BackendPreferences.validate("http://10.0.2.2:8000")
        assertTrue(result is BackendPreferences.ValidationResult.Valid)
        assertEquals("http://10.0.2.2:8000", (result as BackendPreferences.ValidationResult.Valid).normalizedUrl)
    }

    @Test
    fun testValidHttpsUrl() {
        val result = BackendPreferences.validate("https://analyzer.example.com")
        assertTrue(result is BackendPreferences.ValidationResult.Valid)
        assertEquals("https://analyzer.example.com", (result as BackendPreferences.ValidationResult.Valid).normalizedUrl)
    }

    @Test
    fun testTrailingSlashStripped() {
        val result = BackendPreferences.validate("http://192.168.1.100:8000///")
        assertTrue(result is BackendPreferences.ValidationResult.Valid)
        assertEquals("http://192.168.1.100:8000", (result as BackendPreferences.ValidationResult.Valid).normalizedUrl)
    }

    @Test
    fun testEmptyUrlRejected() {
        val result = BackendPreferences.validate("   ")
        assertTrue(result is BackendPreferences.ValidationResult.Invalid)
    }

    @Test
    fun testMissingSchemeRejected() {
        val result = BackendPreferences.validate("10.0.2.2:8000")
        assertTrue(result is BackendPreferences.ValidationResult.Invalid)
    }

    @Test
    fun testUnsupportedSchemeRejected() {
        val ftpResult = BackendPreferences.validate("ftp://10.0.2.2:8000")
        assertTrue(ftpResult is BackendPreferences.ValidationResult.Invalid)

        val jsResult = BackendPreferences.validate("javascript:alert(1)")
        assertTrue(jsResult is BackendPreferences.ValidationResult.Invalid)
    }

    @Test
    fun testInvalidPortRejected() {
        val result = BackendPreferences.validate("http://localhost:99999")
        assertTrue(result is BackendPreferences.ValidationResult.Invalid)
    }
}
