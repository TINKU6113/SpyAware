package com.spyaware.analyzer

/**
 * Definition representing an external SpyAware security module application.
 */
data class ModuleDefinition(
    val id: String,
    val displayName: String,
    val subtitle: String,
    val packageName: String,
    val assetFileName: String,
    val minSdk: Int,
    val targetSdk: Int,
    val description: String,
    val knownCertSha256: String? = null
) {
    companion object {
        /**
         * Module 4: Network Security Analyzer
         * Application ID: com.spyaware.network
         * APK: SpyAware-Module4-Network.apk
         */
        val MODULE_4 = ModuleDefinition(
            id = "module_4",
            displayName = "Network Security Analyzer",
            subtitle = "Network monitoring and security analysis.",
            packageName = "com.spyaware.network",
            assetFileName = "SpyAware-Module4-Network.apk",
            minSdk = 26,
            targetSdk = 34,
            description = "Network monitoring and security analysis.",
            knownCertSha256 = "a3f142012c2f56b33c742c2a86c767bbad30b9eaf52cb5345eacfbef051667a7"
        )

        /**
         * Module 5: BLE Surveillance Detector
         * Application ID: com.example.spyaware
         * APK: SpyAware-Module5-BLE.apk
         */
        val MODULE_5 = ModuleDefinition(
            id = "module_5",
            displayName = "BLE Surveillance Detector",
            subtitle = "Detect nearby Bluetooth Low Energy devices and investigate suspicious device behavior.",
            packageName = "com.example.spyaware",
            assetFileName = "SpyAware-Module5-BLE.apk",
            minSdk = 31,
            targetSdk = 36,
            description = "Detect nearby Bluetooth Low Energy devices and investigate suspicious device behavior.",
            knownCertSha256 = "a14f40592d4d5e7abbbc3ca381f176433ad9101aa3955930eed96ac386e89c0c"
        )

        val ALL_MODULES = listOf(MODULE_4, MODULE_5)

        fun findById(idOrPackage: String): ModuleDefinition? {
            val query = idOrPackage.trim()
            return ALL_MODULES.firstOrNull {
                it.id.equals(query, ignoreCase = true) ||
                        it.packageName.equals(query, ignoreCase = true)
            }
        }
    }
}
