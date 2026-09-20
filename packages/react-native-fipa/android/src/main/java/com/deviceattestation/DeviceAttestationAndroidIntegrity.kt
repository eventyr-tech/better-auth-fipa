package com.deviceattestation

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal class DeviceAttestationAndroidIntegrity(context: ReactApplicationContext) :
    NativeAndroidIntegritySpec(context) {
    private val keys = AndroidAttestedKey(context.applicationContext)
    private val workers =
        ThreadPoolExecutor(2, 2, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(64))
    private val pending = ConcurrentHashMap<Promise, Boolean>()
    @Volatile private var invalidated = false

    private fun reject(promise: Promise, error: Throwable?) {
        if (pending.remove(promise) != null)
            promise.reject(
                (error as? NativeFailure)?.code ?: "native_unavailable",
                "The native operation could not be completed.",
            )
    }

    private fun resolve(promise: Promise, value: Any?) {
        if (pending.remove(promise) != null) promise.resolve(value)
    }

    private fun execute(promise: Promise, block: () -> Any?) {
        pending[promise] = true
        if (invalidated) {
            reject(promise, null)
            return
        }
        try {
            workers.execute {
                try {
                    resolve(promise, block())
                } catch (error: Exception) {
                    reject(promise, error)
                }
            }
        } catch (error: Exception) {
            reject(promise, error)
        }
    }

    override fun inspectKey(alias: String, promise: Promise) =
        execute(promise) { keys.inspect(alias) }

    override fun createKey(
        alias: String,
        attestationChallenge: String,
        securityLevel: String,
        promise: Promise,
    ) = execute(promise) { keys.create(alias, attestationChallenge, securityLevel) }

    override fun certificateChain(alias: String, expectedThumbprint: String, promise: Promise) =
        execute(promise) { Arguments.fromList(keys.certificateChain(alias, expectedThumbprint)) }

    override fun removeKey(alias: String, expectedThumbprint: String, promise: Promise) =
        execute(promise) {
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
    ) = execute(promise) { keys.sign(alias, expectedThumbprint, url, method, accessToken, nonce) }

    override fun sha256Utf8(value: String, promise: Promise) =
        execute(promise) { FirstPartyCrypto.sha256Utf8(value) }

    override fun standardIntegrity(
        cloudProjectNumber: String,
        requestHash: String,
        promise: Promise,
    ) {
        pending[promise] = true
        if (invalidated) {
            reject(promise, null)
            return
        }
        try {
            AndroidPlayIntegrity.coordinator(reactApplicationContext)
                .request(cloudProjectNumber, requestHash)
                .whenComplete { value, error ->
                    if (error != null) reject(promise, error) else resolve(promise, value)
                }
        } catch (error: Exception) {
            reject(promise, error)
        }
    }

    override fun invalidate() {
        invalidated = true
        workers.shutdownNow()
        pending.keys.forEach { reject(it, null) }
        super.invalidate()
    }
}
