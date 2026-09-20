package com.deviceattestation

import java.net.Authenticator
import java.net.CookieHandler
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.PasswordAuthentication
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import okio.GzipSink
import okio.buffer
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class FirstPartyHTTPTest {
    private val server = MockWebServer().apply { start() }
    private val clients = mutableListOf<FirstPartyHTTPClient>()
    private val client = newClient()

    private fun newClient(builder: OkHttpClient.Builder = OkHttpClient.Builder()) =
        FirstPartyHTTPClient(builder).also { clients.add(it) }

    private fun id() = FirstPartyCrypto.randomToken()

    private fun send(
        requestId: String = id(),
        url: String = server.url("/token").toString(),
        method: String = "POST",
        headers: String =
            "{\"content-type\":\"application/x-www-form-urlencoded\",\"DPoP\":\"proof\"}",
        body: String? = "grant_type=refresh_token&refresh_token=secret",
        maximum: Double = 4096.0,
        timeout: Double = 3000.0,
        loopback: Boolean = true,
        transport: FirstPartyHTTPClient = client,
    ) = transport.send(requestId, url, method, headers, body, maximum, timeout, loopback)

    private fun result(output: CompletableFuture<FirstPartyHTTPResponse>) =
        output.get(8, TimeUnit.SECONDS)

    private fun rejected(code: String, output: CompletableFuture<FirstPartyHTTPResponse>) {
        try {
            result(output)
            fail("Expected $code")
        } catch (error: ExecutionException) {
            assertTrue(error.cause is NativeFailure)
            assertEquals(code, (error.cause as NativeFailure).code)
            assertNull(error.cause!!.cause)
        }
    }

    @After
    fun cleanup() {
        clients.forEach { it.close() }
        server.shutdown()
    }

    @Test
    fun preservesProtocolBytesAndJSONErrorResponses() {
        server.enqueue(
            MockResponse()
                .setResponseCode(403)
                .setHeader("DPoP-Nonce", "next")
                .setBody("{\"error\":\"insufficient_authorization\",\"message\":\"é\"}")
        )
        val response = result(send())
        assertEquals(403, response.status)
        assertTrue(response.body.contains("é"))
        assertEquals(server.url("/token").toString(), response.url)
        assertEquals(
            "next",
            Json.parseToJsonElement(response.headersJSON)
                .jsonObject["dpop-nonce"]!!
                .jsonPrimitive
                .content,
        )
        val request = server.takeRequest(1, TimeUnit.SECONDS)!!
        assertEquals("POST", request.method)
        assertEquals("proof", request.getHeader("DPoP"))
        assertEquals("grant_type=refresh_token&refresh_token=secret", request.body.readUtf8())
    }

    @Test
    fun rejectsEveryRedirectWithoutFollowingOrLeakingCredentials() {
        MockWebServer().use { target ->
            target.start()
            for (code in listOf(300, 301, 302, 303, 304, 307, 308)) {
                server.enqueue(
                    MockResponse()
                        .setResponseCode(code)
                        .setHeader("Location", target.url("/stolen"))
                )
                rejected("http_redirect_rejected", send())
            }
            assertEquals(7, server.requestCount)
            assertEquals(0, target.requestCount)
        }
    }

    @Test
    fun neverRetriesOneUsePOSTOnResponsesOrDisconnect() {
        for (code in listOf(401, 408, 421, 503)) {
            server.enqueue(
                MockResponse()
                    .setResponseCode(code)
                    .setHeader("Retry-After", "0")
                    .setHeader("WWW-Authenticate", "Basic realm=private")
            )
            assertEquals(code, result(send()).status)
        }
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        rejected("http_failed", send())
        assertEquals(5, server.requestCount)
    }

    @Test
    fun preventsBodyless503FollowupBeforeSecondSend() {
        server.enqueue(MockResponse().setResponseCode(503).setHeader("Retry-After", "0"))
        rejected("http_failed", send(method = "GET", body = null))
        assertEquals(1, server.requestCount)
    }

    @Test
    fun rejectsUntrustedTLSWithoutExposingCredentials() {
        MockWebServer().use { tls ->
            val certificate =
                HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
            val credentials = HandshakeCertificates.Builder().heldCertificate(certificate).build()
            tls.useHttps(credentials.sslSocketFactory(), false)
            tls.start()
            rejected("http_failed", send(url = tls.url("/token").toString(), loopback = false))
            // TLS handshakes can be recorded, but no HTTP headers/body may reach the server.
            val request = tls.takeRequest(1, TimeUnit.SECONDS)
            assertTrue(request == null || request.requestLine.isEmpty())
        }
    }

    @Test
    fun usesCertificateAndHostnameValidation() {
        for (hostname in listOf("localhost", "wrong.example")) {
            MockWebServer().use { tls ->
                val certificate =
                    HeldCertificate.Builder().addSubjectAlternativeName(hostname).build()
                tls.useHttps(
                    HandshakeCertificates.Builder()
                        .heldCertificate(certificate)
                        .build()
                        .sslSocketFactory(),
                    false,
                )
                tls.start()
                tls.enqueue(MockResponse().setBody("secure"))
                val trust =
                    HandshakeCertificates.Builder()
                        .addTrustedCertificate(certificate.certificate)
                        .build()
                val transport =
                    newClient(
                        OkHttpClient.Builder()
                            .sslSocketFactory(trust.sslSocketFactory(), trust.trustManager)
                    )
                val output =
                    send(
                        url = tls.url("/token").toString(),
                        loopback = false,
                        transport = transport,
                    )
                if (hostname == "localhost") assertEquals("secure", result(output).body)
                else rejected("http_failed", output)
            }
        }
    }

    @Test
    fun isolatesAmbientCookiesCredentialsAndResponseCookies() {
        val originalCookies = CookieHandler.getDefault()
        // getDefault is a JDK API absent from Android's compile stubs. This test
        // runs only in the host JVM and must restore its ambient authenticator.
        val originalAuth =
            Authenticator::class.java.getMethod("getDefault").invoke(null) as Authenticator?
        val authCalls = AtomicInteger()
        try {
            val cookies = CookieManager(null, CookiePolicy.ACCEPT_ALL)
            cookies.put(
                server.url("/").toUri(),
                mapOf("Set-Cookie" to listOf("ambient=secret; Path=/")),
            )
            CookieHandler.setDefault(cookies)
            Authenticator.setDefault(
                object : Authenticator() {
                    override fun getPasswordAuthentication(): PasswordAuthentication {
                        authCalls.incrementAndGet()
                        return PasswordAuthentication("ambient", "secret".toCharArray())
                    }
                }
            )
            server.enqueue(
                MockResponse()
                    .setHeader("Set-Cookie", "native=secret; Path=/")
                    .setHeader("Set-Cookie2", "old=secret")
            )
            val response = result(send())
            assertFalse(response.headersJSON.contains("cookie"))
            server.enqueue(
                MockResponse()
                    .setResponseCode(401)
                    .setHeader("WWW-Authenticate", "Basic realm=private")
            )
            assertEquals(401, result(send()).status)
            repeat(2) {
                val request = server.takeRequest(1, TimeUnit.SECONDS)!!
                assertNull(request.getHeader("Cookie"))
                assertNull(request.getHeader("Authorization"))
            }
            assertEquals(0, authCalls.get())
            assertEquals(1, cookies.cookieStore.cookies.size)
        } finally {
            CookieHandler.setDefault(originalCookies)
            Authenticator.setDefault(originalAuth)
        }
    }

    @Test
    fun doesNotCacheAuthorizationResponses() {
        server.enqueue(
            MockResponse().setHeader("Cache-Control", "public, max-age=3600").setBody("first")
        )
        server.enqueue(MockResponse().setBody("second"))
        assertEquals("first", result(send(method = "GET", body = null)).body)
        assertEquals("second", result(send(method = "GET", body = null)).body)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun enforcesDeclaredStreamedAndDecodedByteLimits() {
        server.enqueue(MockResponse().setBody("x".repeat(17)))
        rejected("http_response_too_large", send(maximum = 16.0))
        server.enqueue(MockResponse().setChunkedBody("x".repeat(17), 3))
        rejected("http_response_too_large", send(maximum = 16.0))
        val compressed = Buffer()
        GzipSink(compressed).buffer().use { it.writeUtf8("x".repeat(10000)) }
        server.enqueue(MockResponse().setHeader("Content-Encoding", "gzip").setBody(compressed))
        rejected("http_response_too_large", send(maximum = 100.0))
        server.enqueue(MockResponse().setBody("é".repeat(8)))
        assertEquals("é".repeat(8), result(send(maximum = 16.0)).body)
    }

    @Test
    fun rejectsMalformedUTF8AndExcessiveHeaders() {
        server.enqueue(MockResponse().setBody(Buffer().write(byteArrayOf(0xC3.toByte(), 0x28))))
        rejected("http_invalid_response", send())
        server.enqueue(MockResponse().setHeader("X-Padding", "x".repeat(16384)))
        rejected("http_invalid_response", send())
    }

    @Test
    fun invalidRequestsNeverReachTheNetwork() {
        for (url in
            listOf(
                "http://example.com",
                "file:///etc/passwd",
                "https://user:secret@localhost/",
                "https://localhost/#fragment",
                "https://localhost/a/../token",
                "https://localhost:0/token",
                "https://LOCALHOST/token",
                "https://localhost\\@evil.example/",
            )) rejected("http_invalid_request", send(url = url))
        rejected("http_invalid_request", send(loopback = false))
        rejected("http_invalid_request", send(method = "TRACE"))
        rejected("http_invalid_request", send(method = "GET"))
        rejected("http_invalid_request", send(requestId = "invalid"))
        for (maximum in
            listOf(0.0, -1.0, 1.5, 1048577.0, Double.NaN, Double.POSITIVE_INFINITY)) rejected(
            "http_invalid_request",
            send(maximum = maximum),
        )
        for (timeout in listOf(999.0, 120001.0, 1000.5, Double.NaN)) rejected(
            "http_invalid_request",
            send(timeout = timeout),
        )
        rejected("http_invalid_request", send(body = "x".repeat(2097153)))
        rejected("http_invalid_request", send(body = "\uD800"))
        assertEquals(0, server.requestCount)
    }

    @Test
    fun rejectsHeadersThatCouldSmuggleCredentialsOrChangeFraming() {
        for (name in
            listOf(
                "Host",
                "Cookie",
                "Cookie2",
                "Proxy-Authorization",
                "Content-Length",
                "Transfer-Encoding",
                "Connection",
                "Upgrade",
                "TE",
                "Trailer",
            )) rejected("http_invalid_request", send(headers = "{\"$name\":\"bad\"}"))
        for (headers in
            listOf(
                "[]",
                "{\"x\":true}",
                "{\"x\":null}",
                "{\"x\":{}}",
                "{\"x\":[]}",
                "{\"x\":\"a\\r\\nb\"}",
                "{\"x\":\"é\"}",
                "{\"DPoP\":\"a\",\"dpop\":\"b\"}",
                "{\"x\":\"${"x".repeat(16385)}\"}",
                "{\"x\":" + "[".repeat(10000),
            )) rejected("http_invalid_request", send(headers = headers))
        assertEquals(0, server.requestCount)
    }

    @Test
    fun cancellationBeforeSendAndDuringResponseCannotReturnTokens() {
        val early = id()
        client.cancel(early)
        rejected("http_cancelled", send(requestId = early))
        assertEquals(0, server.requestCount)
        val active = id()
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        val output = send(requestId = active)
        assertNotNull(server.takeRequest(1, TimeUnit.SECONDS))
        client.cancel(active)
        rejected("http_cancelled", output)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun totalDeadlineBoundsSlowDripResponse() {
        server.enqueue(
            MockResponse().setBody("secret-token").throttleBody(1, 200, TimeUnit.MILLISECONDS)
        )
        val start = System.nanoTime()
        rejected("http_failed", send(timeout = 1000.0))
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 2500)
    }

    @Test
    fun cancellationTombstonesAreBoundedAndExpire() {
        var now = 0L
        val transport = FirstPartyHTTPClient(nowNanos = { now }).also { clients.add(it) }
        repeat(129) { transport.cancel(id()) }
        rejected("http_cancelled", send(transport = transport))
        now = TimeUnit.SECONDS.toNanos(121)
        server.enqueue(MockResponse().setBody("fresh"))
        assertEquals("fresh", result(send(transport = transport)).body)
    }

    @Test
    fun capsOutstandingCallsAndRejectsDuplicateIds() {
        val requests = mutableListOf<Pair<String, CompletableFuture<FirstPartyHTTPResponse>>>()
        repeat(32) {
            server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
            val requestId = id()
            requests.add(requestId to send(requestId = requestId, timeout = 120000.0))
        }
        rejected("http_unavailable", send(requestId = requests[0].first))
        rejected("http_unavailable", send())
        requests.forEach {
            client.cancel(it.first)
            rejected("http_cancelled", it.second)
        }
    }

    @Test
    fun bridgeShutdownCancelsCallsAndRejectsNewWork() {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        val output = send()
        assertNotNull(server.takeRequest(1, TimeUnit.SECONDS))
        client.close()
        rejected("http_cancelled", output)
        rejected("http_unavailable", send())
    }

    @Test
    fun totalDeadlineResolvesWhilePlatformDNSIsBlocked() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val transport =
            newClient(
                OkHttpClient.Builder()
                    .dns(
                        object : okhttp3.Dns {
                            override fun lookup(hostname: String): List<java.net.InetAddress> {
                                entered.countDown()
                                check(release.await(8, TimeUnit.SECONDS))
                                return listOf(java.net.InetAddress.getLoopbackAddress())
                            }
                        }
                    )
            )
        try {
            val output =
                send(url = "https://dns.example/token", timeout = 1000.0, transport = transport)
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            rejected("http_failed", output)
            assertEquals(1L, release.count)
        } finally {
            release.countDown()
        }
    }

    @Test
    fun callbackCannotWinAfterDeadlineEvenIfTimerHasNotFired() {
        var now = 0L
        val transport = FirstPartyHTTPClient(nowNanos = { now }).also { clients.add(it) }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        server.dispatcher =
            object : okhttp3.mockwebserver.Dispatcher() {
                override fun dispatch(
                    request: okhttp3.mockwebserver.RecordedRequest
                ): MockResponse {
                    entered.countDown()
                    check(release.await(8, TimeUnit.SECONDS))
                    return MockResponse().setBody("late-token")
                }
            }
        try {
            val output = send(timeout = 120000.0, transport = transport)
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            now = TimeUnit.SECONDS.toNanos(121)
            release.countDown()
            rejected("http_failed", output)
        } finally {
            release.countDown()
        }
    }
}
