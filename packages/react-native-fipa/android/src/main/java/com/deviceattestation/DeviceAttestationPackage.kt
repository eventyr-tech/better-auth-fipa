package com.deviceattestation

import com.facebook.react.BaseReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.model.ReactModuleInfo
import com.facebook.react.module.model.ReactModuleInfoProvider

/** Other lifecycle modules will be added before enabling Android autolinking. */
class DeviceAttestationPackage : BaseReactPackage() {
    override fun getModule(name: String, reactContext: ReactApplicationContext): NativeModule? =
        when (name) {
            NativeAndroidIntegritySpec.NAME -> DeviceAttestationAndroidIntegrity(reactContext)
            NativeAndroidVaultRecoverySpec.NAME ->
                DeviceAttestationAndroidVaultRecovery(reactContext)
            NativeSessionVaultSpec.NAME -> DeviceAttestationSessionVault(reactContext)
            NativeFirstPartyTransportSpec.NAME -> DeviceAttestationFirstPartyTransport(reactContext)
            else -> null
        }

    override fun getReactModuleInfoProvider() = ReactModuleInfoProvider {
        mapOf(
            NativeAndroidVaultRecoverySpec.NAME to
                ReactModuleInfo(
                    NativeAndroidVaultRecoverySpec.NAME,
                    DeviceAttestationAndroidVaultRecovery::class.java.name,
                    false,
                    false,
                    false,
                    true,
                ),
            NativeFirstPartyTransportSpec.NAME to
                ReactModuleInfo(
                    NativeFirstPartyTransportSpec.NAME,
                    DeviceAttestationFirstPartyTransport::class.java.name,
                    false,
                    false,
                    false,
                    true,
                ),
            NativeAndroidIntegritySpec.NAME to
                ReactModuleInfo(
                    NativeAndroidIntegritySpec.NAME,
                    DeviceAttestationAndroidIntegrity::class.java.name,
                    false,
                    false,
                    false,
                    true,
                ),
            NativeSessionVaultSpec.NAME to
                ReactModuleInfo(
                    NativeSessionVaultSpec.NAME,
                    DeviceAttestationSessionVault::class.java.name,
                    false,
                    false,
                    false,
                    true,
                ),
        )
    }
}
