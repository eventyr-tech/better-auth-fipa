package com.deviceattestation

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

internal fun interface StandardTokenProvider {
    fun request(hash: String): CompletableFuture<String>
}

internal fun interface StandardTokenFactory {
    fun prepare(project: Long): CompletableFuture<StandardTokenProvider>
}

/**
 * Shares warm-up, never tokens. Late warm-up cannot populate an expired entry. Each operation has
 * one total deadline and no hidden retry or classic fallback.
 */
internal class StandardIntegrityCoordinator(
    private val factory: StandardTokenFactory,
    private val timer: ScheduledExecutorService,
    private val timeoutMillis: Long = 30000,
    private val nowNanos: () -> Long = System::nanoTime,
) {
    private class Entry(val pending: CompletableFuture<StandardTokenProvider>) {
        var provider: StandardTokenProvider? = null
    }

    private val entries = mutableMapOf<Long, Entry>()
    private var active = 0
    private val lock = Any()

    fun request(projectNumber: String, hash: String): CompletableFuture<String> {
        val project = projectNumber.toLongOrNull()
        requireNative(
            projectNumber.matches(Regex("[1-9][0-9]{0,18}")) && project != null && project > 0,
            "integrity_invalid_input",
        )
        FirstPartyCrypto.decodeDigest(hash)
        synchronized(lock) {
            requireNative(active < 16, "integrity_busy")
            active++
        }
        val deadline = nowNanos() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        val output = CompletableFuture<String>()
        val timeout =
            timer.schedule(
                { output.completeExceptionally(NativeFailure("integrity_timeout")) },
                timeoutMillis,
                TimeUnit.MILLISECONDS,
            )
        output.whenComplete { _, _ ->
            timeout.cancel(false)
            synchronized(lock) { active-- }
        }
        try {
            provider(project!!).whenComplete providerComplete@{ provider, failure ->
                if (output.isDone) return@providerComplete
                if (nowNanos() - deadline >= 0) {
                    output.completeExceptionally(NativeFailure("integrity_timeout"))
                    return@providerComplete
                }
                if (failure != null) {
                    output.completeExceptionally(NativeFailure("integrity_unavailable"))
                    return@providerComplete
                }
                try {
                    provider.request(hash).whenComplete requestComplete@{ token, error ->
                        if (nowNanos() - deadline >= 0) {
                            output.completeExceptionally(NativeFailure("integrity_timeout"))
                            return@requestComplete
                        }
                        if (error != null) {
                            if (
                                error is NativeFailure && error.code == "integrity_provider_invalid"
                            )
                                synchronized(lock) {
                                    if (entries[project]?.provider === provider)
                                        entries.remove(project)
                                }
                            output.completeExceptionally(NativeFailure("integrity_unavailable"))
                        } else if (
                            token == null || token.isEmpty() || token.toByteArray().size > 32768
                        ) {
                            output.completeExceptionally(
                                NativeFailure("integrity_invalid_response")
                            )
                        } else output.complete(token)
                    }
                } catch (_: Exception) {
                    output.completeExceptionally(NativeFailure("integrity_unavailable"))
                }
            }
        } catch (_: Exception) {
            output.completeExceptionally(NativeFailure("integrity_unavailable"))
        }
        return output
    }

    private fun provider(project: Long): CompletableFuture<StandardTokenProvider> =
        synchronized(lock) {
            entries[project]?.let {
                return@synchronized it.pending
            }
            requireNative(entries.size < 4, "integrity_busy")
            val deadline = nowNanos() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            val output = CompletableFuture<StandardTokenProvider>()
            val entry = Entry(output)
            entries[project] = entry
            val timeout =
                timer.schedule(
                    {
                        synchronized(lock) {
                            if (entries[project] === entry && !output.isDone) {
                                entries.remove(project)
                                output.completeExceptionally(NativeFailure("integrity_timeout"))
                            }
                        }
                    },
                    timeoutMillis,
                    TimeUnit.MILLISECONDS,
                )
            output.whenComplete { _, _ -> timeout.cancel(false) }
            try {
                factory.prepare(project).whenComplete { provider, error ->
                    synchronized(lock) {
                        if (entries[project] === entry && !output.isDone) {
                            if (nowNanos() - deadline >= 0 || error != null || provider == null) {
                                entries.remove(project)
                                output.completeExceptionally(NativeFailure("integrity_unavailable"))
                            } else {
                                entry.provider = provider
                                output.complete(provider)
                            }
                        }
                    }
                }
            } catch (_: Exception) {
                entries.remove(project)
                output.completeExceptionally(NativeFailure("integrity_unavailable"))
            }
            output
        }
}
