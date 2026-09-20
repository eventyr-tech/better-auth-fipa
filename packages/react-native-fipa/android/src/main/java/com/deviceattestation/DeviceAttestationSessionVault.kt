package com.deviceattestation

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal class DeviceAttestationSessionVault(context: ReactApplicationContext) :
    NativeSessionVaultSpec(context) {
    private val vault = SessionVault(AndroidVaultStorage.create(context))
    private val worker = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(64))
    private val pending = ConcurrentHashMap<Promise, Boolean>()
    @Volatile private var invalidated = false

    private fun reject(promise: Promise, error: Exception?) {
        if (pending.remove(promise) != null) {
            val code =
                (error as? NativeFailure)?.code?.takeIf { it.startsWith("vault_") }
                    ?: "vault_storage_failed"
            promise.reject(code, "Unable to complete secure session storage operation.")
        }
    }

    private fun run(promise: Promise, operation: () -> Any?) {
        pending[promise] = true
        if (invalidated) {
            reject(promise, NativeFailure("vault_unavailable"))
            return
        }
        try {
            worker.execute {
                try {
                    val result = operation()
                    if (pending.remove(promise) != null) promise.resolve(result)
                } catch (error: Exception) {
                    reject(promise, error)
                }
            }
        } catch (error: Exception) {
            reject(promise, error)
        }
    }

    override fun acquire(
        storageNamespace: String,
        slotId: String,
        accessibility: String,
        leaseMilliseconds: Double,
        preserveSession: Boolean,
        promise: Promise,
    ) =
        run(promise) {
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
        run(promise) {
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
        run(promise) {
            vault.renew(storageNamespace, slotId, leaseId, generation, leaseMilliseconds)
            null
        }

    override fun abandon(
        storageNamespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        promise: Promise,
    ) = run(promise) { vault.abandon(storageNamespace, slotId, leaseId, generation).toDouble() }

    override fun invalidate(
        storageNamespace: String,
        slotId: String,
        accessibility: String,
        promise: Promise,
    ) = run(promise) { vault.invalidate(storageNamespace, slotId, accessibility).toDouble() }

    override fun discard(
        storageNamespace: String,
        slotId: String,
        generation: Double,
        promise: Promise,
    ) = run(promise) { vault.discard(storageNamespace, slotId, generation) }

    override fun saveIdentity(
        storageNamespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        identityJSON: String,
        promise: Promise,
    ) =
        run(promise) {
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
        run(promise) {
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
        run(promise) {
            vault.release(storageNamespace, slotId, leaseId, generation)
            null
        }

    override fun cancelInteraction(
        storageNamespace: String,
        slotId: String,
        accessibility: String,
        promise: Promise,
    ) =
        run(promise) {
            val result = vault.cancelInteraction(storageNamespace, slotId, accessibility)
            Arguments.createMap().apply {
                putString("sessionJSON", result.sessionJSON)
                putBoolean("cancelled", result.cancelled)
            }
        }

    override fun invalidate() {
        invalidated = true
        worker.shutdownNow()
        pending.keys.forEach { reject(it, NativeFailure("vault_unavailable")) }
        super.invalidate()
    }
}
