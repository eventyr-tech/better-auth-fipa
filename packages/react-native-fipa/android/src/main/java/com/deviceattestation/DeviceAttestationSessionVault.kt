package com.deviceattestation

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext

internal class DeviceAttestationSessionVault(context: ReactApplicationContext) :
    NativeSessionVaultSpec(context) {
    private val vault = SessionVault(AndroidVaultStorage.create(context))
    private val operations =
        BridgeOperations(
            1,
            64,
            { error ->
                (error as? NativeFailure)?.code?.takeIf { it.startsWith("vault_") }
                    ?: "vault_storage_failed"
            },
            "Unable to complete secure session storage operation.",
            NativeFailure("vault_unavailable"),
        )

    override fun acquire(
        storageNamespace: String,
        slotId: String,
        accessibility: String,
        leaseMilliseconds: Double,
        preserveSession: Boolean,
        promise: Promise,
    ) =
        operations.execute(promise) {
            val snapshot =
                vault.acquire(
                    storageNamespace,
                    slotId,
                    accessibility,
                    leaseMilliseconds,
                    preserveSession,
                )
            Arguments.createMap().apply {
                putString("leaseId", snapshot.leaseId)
                putDouble("generation", snapshot.generation.toDouble())
                putString("identityJSON", snapshot.identityJSON)
                putString("sessionJSON", snapshot.sessionJSON)
                putBoolean("recoveryRequired", snapshot.recoveryRequired)
            }
        }

    override fun commit(
        storageNamespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        identityJSON: String?,
        sessionJSON: String?,
        recoverySessionJSON: String?,
        hasInteraction: Boolean,
        promise: Promise,
    ) =
        operations.execute(promise) {
            vault
                .commit(
                    storageNamespace,
                    slotId,
                    leaseId,
                    generation,
                    identityJSON,
                    sessionJSON,
                    recoverySessionJSON,
                    hasInteraction,
                )
                .toDouble()
        }

    override fun renew(
        storageNamespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        leaseMilliseconds: Double,
        promise: Promise,
    ) =
        operations.execute(promise) {
            vault.renew(storageNamespace, slotId, leaseId, generation, leaseMilliseconds)
            null
        }

    override fun abandon(
        storageNamespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        promise: Promise,
    ) =
        operations.execute(promise) {
            vault.abandon(storageNamespace, slotId, leaseId, generation).toDouble()
        }

    override fun invalidate(
        storageNamespace: String,
        slotId: String,
        accessibility: String,
        promise: Promise,
    ) =
        operations.execute(promise) {
            vault.invalidate(storageNamespace, slotId, accessibility).toDouble()
        }

    override fun discard(
        storageNamespace: String,
        slotId: String,
        generation: Double,
        promise: Promise,
    ) = operations.execute(promise) { vault.discard(storageNamespace, slotId, generation) }

    override fun saveIdentity(
        storageNamespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        identityJSON: String,
        promise: Promise,
    ) =
        operations.execute(promise) {
            vault.saveIdentity(storageNamespace, slotId, leaseId, generation, identityJSON)
            null
        }

    override fun clearSession(
        storageNamespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        promise: Promise,
    ) =
        operations.execute(promise) {
            vault.clearSession(storageNamespace, slotId, leaseId, generation)
            null
        }

    override fun release(
        storageNamespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        promise: Promise,
    ) =
        operations.execute(promise) {
            vault.release(storageNamespace, slotId, leaseId, generation)
            null
        }

    override fun cancelInteraction(
        storageNamespace: String,
        slotId: String,
        accessibility: String,
        promise: Promise,
    ) =
        operations.execute(promise) {
            val result = vault.cancelInteraction(storageNamespace, slotId, accessibility)
            Arguments.createMap().apply {
                putString("sessionJSON", result.sessionJSON)
                putBoolean("cancelled", result.cancelled)
            }
        }

    override fun invalidate() {
        operations.invalidate()
        super.invalidate()
    }
}
