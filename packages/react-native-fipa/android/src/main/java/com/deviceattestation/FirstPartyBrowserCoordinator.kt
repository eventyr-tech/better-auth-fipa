package com.deviceattestation

import java.net.URI
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

internal data class BrowserRequest(
    val id: String,
    val url: String,
    val redirectUri: String,
    val timeoutMilliseconds: Double,
    val allowInsecureLoopback: Boolean,
)

internal data class BrowserAttachment(val request: BrowserRequest, val shouldLaunch: Boolean)

/**
 * One system authentication presentation per process, owned by its JS runtime. No URLs or callback
 * capabilities are written to helper-activity intents or storage.
 */
internal class FirstPartyBrowserCoordinator(
    private val now: () -> Long,
    private val schedule: (Long, () -> Unit) -> (() -> Unit),
    private val ticket: () -> String = FirstPartyCrypto::randomToken,
) {
    private class Entry(
        val owner: Any,
        val request: BrowserRequest,
        val ticket: String,
        val deadline: Long,
        val output: CompletableFuture<String>,
    ) {
        var stopTimer: (() -> Unit)? = null
        var dismiss: (() -> Unit)? = null
        var launched = false
    }

    private data class Cancelled(val owner: Any, val id: String)

    private var active: Entry? = null
    private val cancelled = mutableMapOf<Cancelled, Long>()
    private var rejectUntil: Long? = null

    @Synchronized
    fun open(
        owner: Any,
        request: BrowserRequest,
        present: (String) -> Unit,
    ): CompletableFuture<String> {
        val output = CompletableFuture<String>()
        try {
            validate(request)
            prune()
            requireNative(
                rejectUntil == null && cancelled.remove(Cancelled(owner, request.id)) == null,
                "browser_cancelled",
            )
            requireNative(active == null, "browser_busy")
            val held =
                Entry(
                    owner,
                    request,
                    ticket(),
                    now() + TimeUnit.MILLISECONDS.toNanos(request.timeoutMilliseconds.toLong()),
                    output,
                )
            active = held
            held.stopTimer =
                schedule(request.timeoutMilliseconds.toLong()) {
                    synchronized(this) { if (active === held) finish(held, "browser_cancelled") }
                }
            try {
                if (active === held) present(held.ticket)
            } catch (_: Exception) {
                if (active === held) finish(held, "browser_unavailable")
            }
        } catch (error: Exception) {
            // Preserve only bounded, library-defined failures.
            val code = (error as? NativeFailure)?.code ?: "browser_unavailable"
            active?.takeIf { it.output === output }?.let { finish(it, code) }
            output.completeExceptionally(NativeFailure(code))
        }
        return output
    }

    @Synchronized
    fun attach(ticket: String, dismiss: () -> Unit): BrowserAttachment? {
        prune()
        val held = active?.takeIf { it.ticket == ticket } ?: return null
        held.dismiss = dismiss
        val launch = !held.launched
        held.launched = true
        return BrowserAttachment(held.request, launch)
    }

    @Synchronized
    fun isActive(ticket: String): Boolean {
        prune()
        return active?.ticket == ticket
    }

    @Synchronized
    fun detached(ticket: String, dismiss: () -> Unit, changingConfiguration: Boolean) {
        val held = active?.takeIf { it.ticket == ticket && it.dismiss === dismiss } ?: return
        held.dismiss = null
        if (!changingConfiguration) finish(held, "browser_cancelled")
    }

    @Synchronized
    fun result(ticket: String, resultCode: Int, callback: String?) {
        prune()
        val held = active?.takeIf { it.ticket == ticket } ?: return
        if (resultCode == 0) {
            finish(held, "browser_cancelled")
            return
        }
        try {
            requireNative(
                held.launched &&
                    resultCode == -1 &&
                    callback != null &&
                    callback.toByteArray().size <= 32768,
                "browser_failed",
            )
            val actual = URI(callback!!)
            val expected = URI(held.request.redirectUri)
            requireNative(
                actual.rawUserInfo == null &&
                    actual.rawFragment == null &&
                    actual.scheme?.lowercase(Locale.ROOT) ==
                        expected.scheme.lowercase(Locale.ROOT) &&
                    actual.rawAuthority == expected.rawAuthority &&
                    path(actual) == path(expected),
                "browser_failed",
            )
            finish(held, null, callback)
        } catch (_: Exception) {
            finish(held, "browser_failed")
        }
    }

    @Synchronized
    fun unavailable(ticket: String) {
        active?.takeIf { it.ticket == ticket }?.let { finish(it, "browser_unavailable") }
    }

    @Synchronized
    fun cancel(owner: Any, id: String) {
        if (!id.matches(Regex("[A-Za-z0-9_-]{43}"))) return
        prune()
        val held = active
        if (held?.owner === owner && held.request.id == id) {
            finish(held, "browser_cancelled")
            return
        }
        val deadline = now() + TimeUnit.SECONDS.toNanos(300)
        if (cancelled.size >= 128) rejectUntil = deadline
        else cancelled[Cancelled(owner, id)] = deadline
    }

    @Synchronized
    fun invalidate(owner: Any) {
        active?.takeIf { it.owner === owner }?.let { finish(it, "browser_cancelled") }
        cancelled.keys.removeAll { it.owner === owner }
    }

    private fun prune() {
        val current = now()
        cancelled.entries.removeAll { current - it.value >= 0 }
        if (rejectUntil?.let { current - it >= 0 } == true) rejectUntil = null
        active?.takeIf { current - it.deadline >= 0 }?.let { finish(it, "browser_cancelled") }
    }

    private fun finish(held: Entry, error: String?, callback: String? = null) {
        if (active !== held) return
        active = null
        held.stopTimer?.invoke()
        try {
            held.dismiss?.invoke()
        } catch (_: Exception) {
            /* Logical cancellation still fences results. */
        }
        held.dismiss = null
        if (error == null) held.output.complete(callback!!)
        else held.output.completeExceptionally(NativeFailure(error))
    }

    companion object {
        private fun path(uri: URI): String =
            if (uri.isOpaque) uri.rawSchemeSpecificPart.substringBefore('?') else uri.rawPath

        private fun validate(request: BrowserRequest) {
            requireNative(
                request.id.matches(Regex("[A-Za-z0-9_-]{43}")) &&
                    request.timeoutMilliseconds.isFinite() &&
                    request.timeoutMilliseconds in 1.0..300000.0 &&
                    request.timeoutMilliseconds % 1 == 0.0 &&
                    request.url.toByteArray().size <= 8192 &&
                    request.redirectUri.toByteArray().size <= 2048,
                "browser_unavailable",
            )
            val authorization = URI(request.url)
            val callback = URI(request.redirectUri)
            requireNative(
                authorization.rawUserInfo == null &&
                    authorization.rawFragment == null &&
                    authorization.host != null &&
                    authorization.port in -1..65535 &&
                    authorization.port != 0 &&
                    (authorization.scheme == "https" ||
                        (request.allowInsecureLoopback &&
                            authorization.scheme == "http" &&
                            FirstPartyLocalOrigin.contains(authorization.host))),
                "browser_unavailable",
            )
            val scheme = callback.scheme?.lowercase(Locale.ROOT)
            requireNative(
                scheme != null &&
                    scheme.matches(Regex("[a-z][a-z0-9+.-]*")) &&
                    scheme !in setOf("http", "javascript", "data", "file", "about", "intent") &&
                    callback.rawUserInfo == null &&
                    callback.rawFragment == null &&
                    (scheme != "https" ||
                        (callback.host != null && callback.port == -1 && !callback.isOpaque)),
                "browser_unavailable",
            )
        }
    }
}
