package com.deviceattestation

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class StandardIntegrityCoordinatorTest {
    private val timer = Executors.newSingleThreadScheduledExecutor()

    @After
    fun close() {
        timer.shutdownNow()
    }

    private fun hash(n: Int) = FirstPartyCrypto.encode(ByteArray(32) { n.toByte() })

    private fun failure(result: CompletableFuture<String>, code: String) {
        try {
            result.get(2, TimeUnit.SECONDS)
            fail("Expected rejection")
        } catch (error: ExecutionException) {
            assertEquals(code, (error.cause as NativeFailure).code)
        }
    }

    @Test
    fun rejectsLateResultsEvenWhenTheDeadlineSchedulerHasNotRun() {
        var now = 0L
        val prepares = mutableListOf<CompletableFuture<StandardTokenProvider>>()
        val core =
            StandardIntegrityCoordinator(
                { CompletableFuture<StandardTokenProvider>().also(prepares::add) },
                timer,
                1000,
                { now },
            )
        val first = core.request("123", hash(1))
        now = TimeUnit.SECONDS.toNanos(2)
        prepares[0].complete { CompletableFuture.completedFuture("late-provider") }
        failure(first, "integrity_timeout")
        val second = core.request("123", hash(2))
        assertEquals(2, prepares.size)
        val token = CompletableFuture<String>()
        prepares[1].complete { token }
        now = TimeUnit.SECONDS.toNanos(4)
        token.complete("late-token")
        failure(second, "integrity_timeout")
    }

    @Test
    fun boundsCachedProjectsAndSanitizesSynchronousProviderFailures() {
        val core =
            StandardIntegrityCoordinator(
                {
                    CompletableFuture.completedFuture(
                        StandardTokenProvider { CompletableFuture.completedFuture("token") }
                    )
                },
                timer,
                1000,
            )
        repeat(4) { assertEquals("token", core.request((it + 1).toString(), hash(it)).get()) }
        failure(core.request("5", hash(5)), "integrity_unavailable")
        val throwing =
            StandardIntegrityCoordinator({ throw IllegalStateException("secret") }, timer, 1000)
        failure(throwing.request("1", hash(1)), "integrity_unavailable")
        val requestThrows =
            StandardIntegrityCoordinator(
                {
                    CompletableFuture.completedFuture(
                        StandardTokenProvider { throw IllegalStateException("secret") }
                    )
                },
                timer,
                1000,
            )
        failure(requestThrows.request("1", hash(1)), "integrity_unavailable")
    }

    @Test
    fun sharesWarmupButNeverTokensAcrossRequests() {
        val prepare = CompletableFuture<StandardTokenProvider>()
        var preparations = 0
        var requests = 0
        val core =
            StandardIntegrityCoordinator(
                {
                    preparations++
                    prepare
                },
                timer,
                1000,
            )
        val first = core.request("123", hash(1))
        val second = core.request("123", hash(2))
        assertEquals(1, preparations)
        assertFalse(first.isDone)
        prepare.complete { requestHash ->
            requests++
            CompletableFuture.completedFuture("token-$requestHash")
        }
        assertEquals("token-${hash(1)}", first.get())
        assertEquals("token-${hash(2)}", second.get())
        assertEquals("token-${hash(3)}", core.request("123", hash(3)).get())
        assertEquals(3, requests)
        assertEquals(1, preparations)
    }

    @Test
    fun expiresHungWarmupAndIgnoresItsLateCompletion() {
        val prepares = mutableListOf<CompletableFuture<StandardTokenProvider>>()
        val core =
            StandardIntegrityCoordinator(
                { CompletableFuture<StandardTokenProvider>().also(prepares::add) },
                timer,
                60,
            )
        failure(core.request("123", hash(1)), "integrity_timeout")
        // Wait for the warm-up's own timer, which is separate from each waiter.
        timer.submit {}.get(1, TimeUnit.SECONDS)
        Thread.sleep(20)
        prepares[0].complete { CompletableFuture.completedFuture("stale") }
        val next = core.request("123", hash(2))
        assertEquals(2, prepares.size)
        prepares[1].complete { CompletableFuture.completedFuture("fresh") }
        assertEquals("fresh", next.get())
    }

    @Test
    fun timesOutRequestWithoutReturningALateToken() {
        val token = CompletableFuture<String>()
        val core =
            StandardIntegrityCoordinator(
                { CompletableFuture.completedFuture(StandardTokenProvider { token }) },
                timer,
                40,
            )
        val output = core.request("123", hash(1))
        failure(output, "integrity_timeout")
        token.complete("late-sensitive-token")
        failure(output, "integrity_timeout")
    }

    @Test
    fun evictsInvalidProviderWithoutHiddenRetry() {
        val preparations = AtomicInteger()
        val core =
            StandardIntegrityCoordinator(
                {
                    val generation = preparations.incrementAndGet()
                    CompletableFuture.completedFuture(
                        StandardTokenProvider {
                            if (generation == 1)
                                CompletableFuture.failedFuture(
                                    NativeFailure("integrity_provider_invalid")
                                )
                            else CompletableFuture.completedFuture("fresh")
                        }
                    )
                },
                timer,
                1000,
            )
        failure(core.request("123", hash(1)), "integrity_unavailable")
        assertEquals(1, preparations.get())
        assertEquals("fresh", core.request("123", hash(2)).get())
        assertEquals(2, preparations.get())
    }

    @Test
    fun retainsProviderOnTransientRequestFailureAndBoundsTokenBytes() {
        var preparations = 0
        var requests = 0
        val core =
            StandardIntegrityCoordinator(
                {
                    preparations++
                    CompletableFuture.completedFuture(
                        StandardTokenProvider {
                            requests++
                            when (requests) {
                                1 -> CompletableFuture.failedFuture(IllegalStateException("secret"))
                                2 -> CompletableFuture.completedFuture("")
                                3 -> CompletableFuture.completedFuture("é".repeat(16385))
                                else -> CompletableFuture.completedFuture("okay")
                            }
                        }
                    )
                },
                timer,
                1000,
            )
        failure(core.request("123", hash(1)), "integrity_unavailable")
        failure(core.request("123", hash(2)), "integrity_invalid_response")
        failure(core.request("123", hash(3)), "integrity_invalid_response")
        assertEquals("okay", core.request("123", hash(4)).get())
        assertEquals(1, preparations)
    }

    @Test
    fun rejectsInvalidInputAndBoundsOutstandingWork() {
        val core = StandardIntegrityCoordinator({ CompletableFuture() }, timer, 1000)
        for (project in listOf("0", "01", "1.2", "-1", "9223372036854775808")) {
            try {
                core.request(project, hash(1))
                fail("Expected rejection")
            } catch (error: NativeFailure) {
                assertEquals("integrity_invalid_input", error.code)
            }
        }
        try {
            core.request("123", "x")
            fail("Expected rejection")
        } catch (error: NativeFailure) {
            assertEquals("key_invalid_input", error.code)
        }
        repeat(16) { core.request("123", hash(it)) }
        try {
            core.request("123", hash(17))
            fail("Expected rejection")
        } catch (error: NativeFailure) {
            assertEquals("integrity_busy", error.code)
        }
    }

    @Test
    fun isolatesCloudProjectsAndRetriesFailedWarmupOnlyOnANewCall() {
        var prepares = 0
        val core =
            StandardIntegrityCoordinator(
                { project ->
                    prepares++
                    if (prepares == 1)
                        CompletableFuture.failedFuture(IllegalStateException("secret"))
                    else
                        CompletableFuture.completedFuture(
                            StandardTokenProvider {
                                CompletableFuture.completedFuture("token-$project")
                            }
                        )
                },
                timer,
                1000,
            )
        failure(core.request("123", hash(1)), "integrity_unavailable")
        assertEquals("token-123", core.request("123", hash(2)).get())
        assertEquals("token-456", core.request("456", hash(3)).get())
        assertEquals(3, prepares)
    }
}
