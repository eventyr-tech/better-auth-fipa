package com.deviceattestation

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext

internal class DeviceAttestationAndroidIntegrity(context: ReactApplicationContext) :
    NativeAndroidIntegritySpec(context) {
    private val keys = AndroidAttestedKey(context.applicationContext)
    private val operations =
        BridgeOperations(
            2,
            64,
            { error -> (error as? NativeFailure)?.code ?: "native_unavailable" },
            "The native operation could not be completed.",
        )

    override fun inspectKey(alias: String, promise: Promise) =
        operations.execute(promise) { keys.inspect(alias) }

    override fun createKey(
        alias: String,
        attestationChallenge: String,
        securityLevel: String,
        promise: Promise,
    ) = operations.execute(promise) { keys.create(alias, attestationChallenge, securityLevel) }

    override fun certificateChain(alias: String, expectedThumbprint: String, promise: Promise) =
        operations.execute(promise) {
            Arguments.fromList(keys.certificateChain(alias, expectedThumbprint))
        }

    override fun removeKey(alias: String, expectedThumbprint: String, promise: Promise) =
        operations.execute(promise) {
            keys.remove(alias, expectedThumbprint)
            null
        }

    override fun signDpop(
        alias: String,
        expectedThumbprint: String,
        url: String,
        method: String,
        accessToken: String?,
        nonce: String?,
        promise: Promise,
    ) =
        operations.execute(promise) {
            keys.sign(alias, expectedThumbprint, url, method, accessToken, nonce)
        }

    override fun sha256Utf8(value: String, promise: Promise) =
        operations.execute(promise) { FirstPartyCrypto.sha256Utf8(value) }

    override fun standardIntegrity(
        cloudProjectNumber: String,
        requestHash: String,
        promise: Promise,
    ) {
        if (!operations.begin(promise)) return
        try {
            AndroidPlayIntegrity.coordinator(reactApplicationContext)
                .request(cloudProjectNumber, requestHash)
                .whenComplete { value, error ->
                    if (error != null) operations.reject(promise, error)
                    else operations.resolve(promise, value)
                }
        } catch (error: Exception) {
            operations.reject(promise, error)
        }
    }

    override fun invalidate() {
        operations.invalidate()
        super.invalidate()
    }
}
