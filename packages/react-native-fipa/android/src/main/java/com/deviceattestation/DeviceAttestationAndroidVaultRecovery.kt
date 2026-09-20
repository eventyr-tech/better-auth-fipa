package com.deviceattestation

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext

/**
 * Explicit all-account ciphertext recovery. Uses the same durable lock/journal as normal vault
 * operations, including across separate RN runtimes/processes.
 */
internal class DeviceAttestationAndroidVaultRecovery(context: ReactApplicationContext) :
    NativeAndroidVaultRecoverySpec(context) {
    private val storage = AndroidVaultStorage.create(context)
    private val operations =
        BridgeOperations(
            1,
            4,
            { error ->
                (error as? NativeFailure)?.code?.takeIf { it.startsWith("vault_") }
                    ?: "vault_storage_failed"
            },
            "Unable to complete secure storage recovery.",
            NativeFailure("vault_unavailable"),
        )

    override fun prepare(promise: Promise) =
        operations.execute(promise) {
            storage.prepareRecovery()?.let { ticket ->
                Arguments.createMap().apply {
                    putString("token", ticket.token)
                    putBoolean("inProgress", ticket.inProgress)
                }
            }
        }

    override fun recover(token: String, promise: Promise) =
        operations.execute(promise) { storage.recover(token) }

    override fun invalidate() {
        operations.invalidate()
        super.invalidate()
    }
}
