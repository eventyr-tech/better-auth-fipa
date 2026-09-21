package com.deviceattestation

import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class FirstPartyBrowserCoordinatorTest {
    private var now = 0L
    private val timers = mutableListOf<() -> Unit>()
    private var stoppedTimers = 0
    private val owner = Any()
    private val other = Any()
    private var current = ""
    private var presentations = 0
    private var dismissals = 0
    private val coordinator =
        FirstPartyBrowserCoordinator(
            { now },
            { _, action ->
                timers.add(action)
                ({ stoppedTimers++ })
            },
        )
    private val dismiss = {
        dismissals++
        Unit
    }

    private fun request(id: String = FirstPartyCrypto.randomToken()) =
        BrowserRequest(
            id,
            "https://auth.example/authorize?request_uri=opaque",
            "com.example:/oauth/callback",
            300000.0,
            false,
        )

    private fun open(
        value: BrowserRequest = request(),
        runtime: Any = owner,
    ): CompletableFuture<String> =
        coordinator.open(runtime, value) {
            current = it
            presentations++
        }

    private fun attach() = coordinator.attach(current, dismiss)!!

    private fun callback() =
        "com.example:/oauth/callback?code=opaque&state=state&iss=https%3A%2F%2Fauth.example"

    private fun rejected(code: String, output: CompletableFuture<String>) {
        try {
            output.get(1, TimeUnit.SECONDS)
            fail("Expected $code")
        } catch (error: ExecutionException) {
            assertEquals(code, (error.cause as NativeFailure).code)
            assertNull(error.cause!!.cause)
        }
    }

    @Test
    fun successReturnsOnlyTheCallbackAndClosesItsOwnedPresentation() {
        val output = open()
        assertTrue(attach().shouldLaunch)
        coordinator.result(current, -1, callback())
        assertEquals(callback(), output.get())
        assertEquals(1, dismissals)
        assertEquals(1, stoppedTimers)
        assertFalse(coordinator.isActive(current))
        coordinator.result(current, -1, callback())
        assertEquals(1, dismissals)
    }

    @Test
    fun onePresentationAcrossRuntimesAndAccounts() {
        val first = open()
        attach()
        rejected("browser_busy", open(runtime = other))
        assertEquals(1, presentations)
        coordinator.invalidate(other)
        assertFalse(first.isDone)
        coordinator.invalidate(owner)
        rejected("browser_cancelled", first)
        assertEquals(1, dismissals)
        open(runtime = other)
        assertEquals(2, presentations)
    }

    @Test
    fun cancelBeforeDispatchPreventsPresentationAndIsRuntimeScoped() {
        val value = request()
        coordinator.cancel(owner, value.id)
        rejected("browser_cancelled", open(value))
        assertEquals(0, presentations)
        coordinator.cancel(owner, value.id)
        val output = open(value, other)
        attach()
        coordinator.cancel(owner, value.id)
        assertFalse(output.isDone)
        coordinator.cancel(other, value.id)
        rejected("browser_cancelled", output)
    }

    @Test
    fun cancellationFencesLateCallbackFromReplacingNewLogin() {
        val value = request()
        val old = open(value)
        attach()
        val oldTicket = current
        coordinator.cancel(owner, value.id)
        rejected("browser_cancelled", old)
        val fresh = open()
        attach()
        coordinator.result(oldTicket, -1, callback())
        assertFalse(fresh.isDone)
        coordinator.result(current, -1, callback())
        assertEquals(callback(), fresh.get())
        assertEquals(2, dismissals)
    }

    @Test
    fun configurationRecreationDoesNotReopenOneUseURL() {
        val output = open()
        val first = attach()
        assertTrue(first.shouldLaunch)
        coordinator.detached(current, dismiss, true)
        assertFalse(output.isDone)
        val recreatedDismiss = {
            dismissals += 10
            Unit
        }
        assertFalse(coordinator.attach(current, recreatedDismiss)!!.shouldLaunch)
        // Destruction of an older activity cannot detach its replacement.
        coordinator.detached(current, dismiss, false)
        assertFalse(output.isDone)
        coordinator.result(current, -1, callback())
        assertEquals(callback(), output.get())
        assertEquals(10, dismissals)
        assertEquals(1, presentations)
    }

    @Test
    fun processRestartHasNoAuthorityToReopenOrAcceptCallback() {
        open()
        attach()
        val restarted = FirstPartyBrowserCoordinator({ now }, { _, _ -> ({}) })
        assertNull(restarted.attach(current, dismiss))
        restarted.result(current, -1, callback())
        assertFalse(restarted.isActive(current))
    }

    @Test
    fun activityDestructionCancelsAndReleasesPresentation() {
        val output = open()
        attach()
        coordinator.detached(current, dismiss, false)
        rejected("browser_cancelled", output)
        assertFalse(coordinator.isActive(current))
        assertEquals(0, dismissals) // already destroyed
        open()
        assertEquals(2, presentations)
    }

    @Test
    fun timerCancellationPreventsLateResultsAndStaleTimerCannotCancelNewFlow() {
        val old = open()
        attach()
        val expired = timers.single()
        expired()
        rejected("browser_cancelled", old)
        val fresh = open()
        attach()
        expired()
        assertFalse(fresh.isDone)
        coordinator.result(current, -1, callback())
        assertEquals(callback(), fresh.get())
    }

    @Test
    fun elapsedDeadlineWinsEvenWhenUITimerHasNotRun() {
        val output = open()
        attach()
        now = TimeUnit.SECONDS.toNanos(301)
        coordinator.result(current, -1, callback())
        rejected("browser_cancelled", output)
        assertEquals(1, dismissals)
    }

    @Test
    fun lateActivityCreationCannotLaunchExpiredOrCancelledRequest() {
        val value = request()
        val output = open(value)
        coordinator.cancel(owner, value.id)
        assertNull(coordinator.attach(current, dismiss))
        rejected("browser_cancelled", output)
        val next = open()
        now = TimeUnit.SECONDS.toNanos(301)
        assertNull(coordinator.attach(current, dismiss))
        rejected("browser_cancelled", next)
    }

    @Test
    fun boundedTombstonesExpireAndInvalidIdsCannotFillThem() {
        repeat(200) { coordinator.cancel(owner, "invalid") }
        open()
        coordinator.invalidate(owner)
        repeat(129) { coordinator.cancel(owner, request().id) }
        rejected("browser_cancelled", open())
        now = TimeUnit.SECONDS.toNanos(301)
        assertFalse(open().isDone)
    }

    @Test
    fun unsupportedProviderAndLaunchFailuresReleaseTheSlot() {
        val output = open()
        attach()
        coordinator.unavailable(current)
        rejected("browser_unavailable", output)
        assertEquals(1, dismissals)
        val failure = coordinator.open(owner, request()) { throw IllegalStateException("secret") }
        rejected("browser_unavailable", failure)
        assertFalse(open().isDone)
    }

    @Test
    fun schedulerFailureDoesNotLeaveABusySlot() {
        val broken =
            FirstPartyBrowserCoordinator({ now }, { _, _ -> throw IllegalStateException("secret") })
        repeat(2) {
            rejected(
                "browser_unavailable",
                broken.open(owner, request()) { fail("Must not present") },
            )
        }
    }

    @Test
    fun cancellationAndUnverifiedResultsNeverReturnCallbacks() {
        for (code in listOf(0, 2, 3, -2, 100)) {
            val output = open()
            attach()
            coordinator.result(current, code, callback())
            rejected(if (code == 0) "browser_cancelled" else "browser_failed", output)
        }
    }

    @Test
    fun nativeChecksRejectWrongTargetsBeforeSDKValidation() {
        for (callback in
            listOf(
                null,
                "https://attacker.example/",
                "com.other:/oauth/callback?code=secret",
                "com.example:/different?code=secret",
                "com.example:/oauth/callback#secret",
                "com.example://user@host/oauth/callback",
                "com.example:/oauth/callback?code=${"a".repeat(32768)}",
                "com.example:/oauth/callback?code=%GG",
            )) {
            val output = open()
            attach()
            coordinator.result(current, -1, callback)
            rejected("browser_failed", output)
        }
    }

    @Test
    fun acceptsHTTPSAndOpaqueSchemesWhileSDKOwnsFullStateAndIssuerChecks() {
        for (uri in listOf("https://callback.example/complete?fixed=one", "com.example:callback")) {
            val value = request().copy(redirectUri = uri)
            val output = open(value)
            attach()
            val callback =
                uri +
                    (if (uri.contains('?')) "&" else "?") +
                    "code=opaque&state=state&iss=https%3A%2F%2Fauth.example"
            coordinator.result(current, -1, callback)
            assertEquals(callback, output.get())
        }
    }

    @Test
    fun invalidConfigurationNeverPresents() {
        for (url in
            listOf(
                "http://example.com/",
                "https://user:secret@auth.example/",
                "https://auth.example/#fragment",
                "file:///secret",
                "https://auth.example:0/",
                "https://auth.example/" + "a".repeat(8192),
            )) rejected("browser_unavailable", open(request().copy(url = url)))
        for (redirect in
            listOf(
                "http://callback.example/",
                "javascript:secret",
                "data:secret",
                "intent:secret",
                "file:///secret",
                "about:blank",
                "https://callback.example:443/",
                "https://user:secret@callback.example/",
                "com.example:/callback#fragment",
                "com.example:/" + "a".repeat(2048),
            )) rejected("browser_unavailable", open(request().copy(redirectUri = redirect)))
        for (timeout in listOf(0.0, 300001.0, 1.5, Double.NaN, Double.POSITIVE_INFINITY)) rejected(
            "browser_unavailable",
            open(request().copy(timeoutMilliseconds = timeout)),
        )
        rejected("browser_unavailable", open(request("bad")))
        assertEquals(0, presentations)
    }

    @Test
    fun cleartextRequiresExplicitLoopbackDevelopmentOptIn() {
        for (host in
            listOf(
                "localhost",
                "eventyr.localhost",
                "deep.eventyr.localhost",
                "EVENTYR.LocalHost",
                "localhost.",
                "eventyr.localhost.",
                "a-b.localhost",
                "127.0.0.1",
                "[::1]",
            )) {
            for (port in listOf("", ":3000")) {
                val value =
                    request().copy(url = "http://$host$port/auth", allowInsecureLoopback = true)
                rejected("browser_unavailable", open(value.copy(allowInsecureLoopback = false)))
                val output = open(value)
                assertEquals(value, attach().request)
                coordinator.invalidate(owner)
                rejected("browser_cancelled", output)
            }
        }
        for (host in
            listOf(
                "notlocalhost",
                "localhost.example.com",
                "eventyr.localhost.evil.com",
                "evil-localhost",
                ".localhost",
                "a..localhost",
                "-a.localhost",
                "a-.localhost",
                "a_b.localhost",
                "localhost..",
                "eventyr.localhost..",
                "192.168.1.1",
                "127.0.0.2",
                "10.0.2.2",
            )) {
            rejected(
                "browser_unavailable",
                open(request().copy(url = "http://$host:3000/", allowInsecureLoopback = true)),
            )
        }
    }
}
