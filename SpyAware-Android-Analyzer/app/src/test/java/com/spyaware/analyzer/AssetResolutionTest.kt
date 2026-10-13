package com.spyaware.analyzer

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AssetResolutionTest {

    private val assetsDir = File("src/main/assets")

    private fun resolveCandidate(path: String): File? {
        val cleanPath = path.substringBefore('?').substringBefore('#').trimStart('/')
        val targetPath = if (cleanPath.isEmpty()) "index.html" else cleanPath

        val candidates = listOf(
            targetPath,
            "dist/$targetPath",
            "assets/$targetPath",
            "dist/assets/$targetPath"
        )

        for (candidate in candidates) {
            val file = File(assetsDir, candidate)
            if (file.exists() && file.isFile) {
                return file
            }
        }
        return null
    }

    @Test
    fun testIndexHtmlExistsAndContainsBackendRouting() {
        val indexFile = File(assetsDir, "index.html")
        assertTrue("index.html must exist in assets", indexFile.exists())
        val content = indexFile.readText()
        assertTrue("index.html must contain __SPYAWARE_API_BASE__", content.contains("__SPYAWARE_API_BASE__"))
        assertTrue("index.html must contain window.fetch override", content.contains("window.fetch"))
        assertTrue("index.html must reference appassets origin api", content.contains("https://appassets.androidplatform.net/api"))
    }

    @Test
    fun testScriptAndCssBundlesResolved() {
        // Test resolving index.html
        val resolvedIndex = resolveCandidate("index.html")
        assertNotNull("index.html should be resolvable", resolvedIndex)

        // Test resolving root path
        val resolvedRoot = resolveCandidate("")
        assertNotNull("empty root path should resolve to index.html", resolvedRoot)

        // Test resolving the Vite JS chunk by stripped path (what WebViewAssetLoader passes)
        val jsFiles = File(assetsDir, "assets").listFiles { _, name -> name.endsWith(".js") } ?: emptyArray()
        assertTrue("At least one JS bundle must exist in assets/assets", jsFiles.isNotEmpty())
        val jsBundleName = jsFiles.first().name
        val resolvedJs = resolveCandidate(jsBundleName)
        assertNotNull("Vite JS bundle ($jsBundleName) must be resolvable from assets", resolvedJs)
        assertTrue(resolvedJs!!.name.endsWith(".js"))

        // Test resolving the CSS bundle by stripped path
        val cssFiles = File(assetsDir, "assets").listFiles { _, name -> name.endsWith(".css") } ?: emptyArray()
        assertTrue("At least one CSS bundle must exist in assets/assets", cssFiles.isNotEmpty())
        val cssBundleName = cssFiles.first().name
        val resolvedCss = resolveCandidate(cssBundleName)
        assertNotNull("Vite CSS bundle ($cssBundleName) must be resolvable from assets", resolvedCss)
        assertTrue(resolvedCss!!.name.endsWith(".css"))

        // Test resolving favicon.svg
        val resolvedFavicon = resolveCandidate("favicon.svg")
        assertNotNull("favicon.svg must be resolvable from assets", resolvedFavicon)
    }

    @Test
    fun testHttpsAppAssetsUrlFormat() {
        val backendUrl = "http://10.0.2.2:8000"
        val encodedBackend = java.net.URLEncoder.encode(backendUrl, "UTF-8")
        val targetUrl = "https://appassets.androidplatform.net/assets/index.html?backend=$encodedBackend"

        val uri = java.net.URI(targetUrl)
        assertTrue("Scheme must be HTTPS", uri.scheme == "https")
        assertTrue("Host must be appassets.androidplatform.net", uri.host == "appassets.androidplatform.net")
        assertTrue("Path must start with /assets/", uri.path.startsWith("/assets/"))
        assertTrue("Query must contain backend param", uri.query.contains("backend="))
    }
}
