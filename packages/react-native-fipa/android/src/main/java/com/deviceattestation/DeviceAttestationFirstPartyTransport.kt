package com.deviceattestation

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Foreground protocol transport. Android enrollment must use the challenge-bound key module; the
 * iOS prepareDpop entry point can never mint an unattested key.
 */
internal class DeviceAttestationFirstPartyTransport(context: ReactApplicationContext) :
    NativeFirstPartyTransportSpec(context) {
    private val client = FirstPartyHTTPClient()
    private val keys = AndroidAttestedKey(context.applicationContext)
    private val worker = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(64))
    private val pending = ConcurrentHashMap<Promise, Boolean>()
    @Volatile private var invalidated = false

    private fun reject(promise: Promise, error: Throwable?) {
        if (pending.remove(promise) != null)
            promise.reject(
                (error as? NativeFailure)?.code ?: "http_unavailable",
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
            worker.execute {
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

    override fun randomToken(promise: Promise) = execute(promise) { FirstPartyCrypto.randomToken() }

    override fun transaction(promise: Promise) =
        execute(promise) {
            val verifier = FirstPartyCrypto.randomToken()
            Arguments.createMap().apply {
                putString("id", FirstPartyCrypto.randomToken())
                putString("verifier", verifier)
                putString("challenge", FirstPartyCrypto.sha256Utf8(verifier))
            }
        }

    override fun prepareDpop(alias: String, promise: Promise) =
        execute(promise) { throw NativeFailure("key_enrollment_required") }

    override fun inspectDpop(alias: String, promise: Promise) =
        execute(promise) { keys.inspect(alias) ?: throw NativeFailure("key_missing") }

    override fun removeDpop(alias: String, expectedThumbprint: String, promise: Promise) =
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

    override fun send(
        requestId: String,
        url: String,
        method: String,
        headersJSON: String,
        body: String?,
        maximumResponseBytes: Double,
        timeoutMilliseconds: Double,
        allowInsecureLoopback: Boolean,
        promise: Promise,
    ) {
        pending[promise] = true
        if (invalidated) {
            reject(promise, null)
            return
        }
        client
            .send(
                requestId,
                url,
                method,
                headersJSON,
                body,
                maximumResponseBytes,
                timeoutMilliseconds,
                allowInsecureLoopback,
            )
            .whenComplete { response, error ->
                if (error != null) reject(promise, error)
                else
                    resolve(
                        promise,
                        Arguments.createMap().apply {
                            putString("url", response.url)
                            putInt("status", response.status)
                            putString("headersJSON", response.headersJSON)
                            putString("body", response.body)
                        },
                    )
            }
    }

    override fun cancel(requestId: String, promise: Promise) {
        client.cancel(requestId)
        promise.resolve(null)
    }

    override fun openBrowser(
        requestId: String,
        url: String,
        redirectUri: String,
        timeoutMilliseconds: Double,
        allowInsecureLoopback: Boolean,
        promise: Promise,
    ) {
        pending[promise] = true
        AndroidFirstPartyBrowser.open(
            this,
            reactApplicationContext,
            BrowserRequest(requestId, url, redirectUri, timeoutMilliseconds, allowInsecureLoopback),
            { invalidated },
        ) { callback, error ->
            if (error != null) reject(promise, error) else resolve(promise, callback)
        }
    }

    override fun cancelBrowser(requestId: String, promise: Promise) {
        AndroidFirstPartyBrowser.cancel(this, requestId) { promise.resolve(null) }
    }

    override fun invalidate() {
        invalidated = true
        AndroidFirstPartyBrowser.invalidate(this)
        client.close()
        worker.shutdownNow()
        pending.keys.forEach { reject(it, null) }
        super.invalidate()
    }
}
