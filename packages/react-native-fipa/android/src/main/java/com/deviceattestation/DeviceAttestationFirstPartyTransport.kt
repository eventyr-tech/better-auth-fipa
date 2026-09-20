package com.deviceattestation

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext

/**
 * Foreground protocol transport. Android enrollment must use the challenge-bound key module; the
 * iOS prepareDpop entry point can never mint an unattested key.
 */
internal class DeviceAttestationFirstPartyTransport(context: ReactApplicationContext) :
    NativeFirstPartyTransportSpec(context) {
    private val client = FirstPartyHTTPClient()
    private val keys = AndroidAttestedKey(context.applicationContext)
    private val operations =
        BridgeOperations(
            1,
            64,
            { error -> (error as? NativeFailure)?.code ?: "http_unavailable" },
            "The native operation could not be completed.",
        )

    override fun randomToken(promise: Promise) =
        operations.execute(promise) { FirstPartyCrypto.randomToken() }

    override fun transaction(promise: Promise) =
        operations.execute(promise) {
            val verifier = FirstPartyCrypto.randomToken()
            Arguments.createMap().apply {
                putString("id", FirstPartyCrypto.randomToken())
                putString("verifier", verifier)
                putString("challenge", FirstPartyCrypto.sha256Utf8(verifier))
            }
        }

    override fun prepareDpop(alias: String, promise: Promise) =
        operations.execute(promise) { throw NativeFailure("key_enrollment_required") }

    override fun inspectDpop(alias: String, promise: Promise) =
        operations.execute(promise) { keys.inspect(alias) ?: throw NativeFailure("key_missing") }

    override fun removeDpop(alias: String, expectedThumbprint: String, promise: Promise) =
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
        if (!operations.begin(promise)) return
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
                if (error != null) operations.reject(promise, error)
                else
                    operations.resolve(
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
        if (!operations.begin(promise)) return
        AndroidFirstPartyBrowser.open(
            this,
            reactApplicationContext,
            BrowserRequest(requestId, url, redirectUri, timeoutMilliseconds, allowInsecureLoopback),
            { operations.invalidated },
        ) { callback, error ->
            if (error != null) operations.reject(promise, error)
            else operations.resolve(promise, callback)
        }
    }

    override fun cancelBrowser(requestId: String, promise: Promise) {
        AndroidFirstPartyBrowser.cancel(this, requestId) { promise.resolve(null) }
    }

    override fun invalidate() {
        operations.invalidate {
            AndroidFirstPartyBrowser.invalidate(this)
            client.close()
        }
        super.invalidate()
    }
}
