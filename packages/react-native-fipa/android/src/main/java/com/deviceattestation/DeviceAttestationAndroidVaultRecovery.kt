package com.deviceattestation

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Explicit all-account ciphertext recovery. Uses the same durable lock/journal as normal vault
 * operations, including across separate RN runtimes/processes.
 */
internal class DeviceAttestationAndroidVaultRecovery(context: ReactApplicationContext) :
    NativeAndroidVaultRecoverySpec(context) {
    private val storage = AndroidVaultStorage.create(context)
    private val worker = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(4))
    private val pending = ConcurrentHashMap<Promise, Boolean>()
    @Volatile private var invalidated = false

    private fun reject(promise: Promise, error: Exception?) {
        if (pending.remove(promise) != null) {
            val code =
                (error as? NativeFailure)?.code?.takeIf { it.startsWith("vault_") }
                    ?: "vault_storage_failed"
            promise.reject(code, "Unable to complete secure storage recovery.")
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

    override fun prepare(promise: Promise) =
        run(promise) {
            storage.prepareRecovery()?.let { ticket ->
                Arguments.createMap().apply {
                    putString("token", ticket.token)
                    putBoolean("inProgress", ticket.inProgress)
                }
            }
        }

    override fun recover(token: String, promise: Promise) = run(promise) { storage.recover(token) }

    override fun invalidate() {
        invalidated = true
        worker.shutdownNow()
        pending.keys.forEach { reject(it, NativeFailure("vault_unavailable")) }
        super.invalidate()
    }
}
