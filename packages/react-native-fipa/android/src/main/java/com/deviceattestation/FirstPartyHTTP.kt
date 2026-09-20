package com.deviceattestation

import java.io.Closeable
import java.io.IOException
import java.net.URI
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.util.Locale
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.serialization.json.*
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import okio.Buffer
import okio.BufferedSink

internal data class FirstPartyHTTPResponse(
    val url: String,
    val status: Int,
    val headersJSON: String,
    val body: String,
)

/**
 * Isolated from React Native's client, ambient cookies, credentials and cache. The constructor seam
 * is internal for JVM TLS tests; it is never a JS option.
 */
internal class FirstPartyHTTPClient(
    builder: OkHttpClient.Builder = OkHttpClient.Builder(),
    private val nowNanos: () -> Long = System::nanoTime,
) : Closeable {
    private class Attempt {
        val sent = AtomicBoolean()
    }

    private class Exchange(
        val call: Call,
        val deadline: Long,
        val output: CompletableFuture<FirstPartyHTTPResponse>,
    ) {
        var timer: ScheduledFuture<*>? = null
    }

    private val lock = Any()
    private val active = mutableMapOf<String, Exchange>()
    private val cancelled = mutableMapOf<String, Long>()
    private var rejectUntil: Long? = null
    private var closed = false
    private val timer =
        Executors.newSingleThreadScheduledExecutor { work ->
            Thread(work, "DeviceAttestation.HTTP.deadline").apply { isDaemon = true }
        }
    private val client =
        builder
            .cookieJar(CookieJar.NO_COOKIES)
            .authenticator(Authenticator.NONE)
            .proxyAuthenticator(Authenticator.NONE)
            .cache(null)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .dispatcher(
                Dispatcher().apply {
                    maxRequests = 32
                    maxRequestsPerHost = 32
                }
            )
            .addNetworkInterceptor { chain ->
                // retryOnConnectionFailure(false) alone does not stop e.g. 503 +
                // Retry-After: 0 follow-ups. Never repeat a proof or consumed token.
                if (
                    chain.request().tag(Attempt::class.java)?.sent?.compareAndSet(false, true) !=
                        true
                )
                    throw IOException("Repeated authentication request rejected.")
                chain.proceed(chain.request())
            }
            .build()

    fun send(
        id: String,
        url: String,
        method: String,
        headersJSON: String,
        body: String?,
        maximumResponseBytes: Double,
        timeoutMilliseconds: Double,
        allowInsecureLoopback: Boolean,
    ): CompletableFuture<FirstPartyHTTPResponse> {
        val output = CompletableFuture<FirstPartyHTTPResponse>()
        try {
            val request =
                request(
                    id,
                    url,
                    method,
                    headersJSON,
                    body,
                    maximumResponseBytes,
                    timeoutMilliseconds,
                    allowInsecureLoopback,
                )
            val timeout = timeoutMilliseconds.toLong()
            synchronized(lock) {
                pruneCancelled()
                requireNative(!closed, "http_unavailable")
                requireNative(cancelled.remove(id) == null && rejectUntil == null, "http_cancelled")
                requireNative(id !in active && active.size < 32, "http_unavailable")
                val call =
                    client
                        .newBuilder()
                        .callTimeout(timeout, TimeUnit.MILLISECONDS)
                        .connectTimeout(timeout, TimeUnit.MILLISECONDS)
                        .readTimeout(timeout, TimeUnit.MILLISECONDS)
                        .writeTimeout(timeout, TimeUnit.MILLISECONDS)
                        .build()
                        .newCall(request)
                val entry =
                    Exchange(call, nowNanos() + TimeUnit.MILLISECONDS.toNanos(timeout), output)
                active[id] = entry
                // Separate deadline resolves even if platform DNS has not returned.
                // Keep the capacity reservation until the network callback ends.
                entry.timer =
                    timer.schedule(
                        {
                            synchronized(lock) {
                                if (active[id] === entry) {
                                    output.completeExceptionally(NativeFailure("http_failed"))
                                    call.cancel()
                                }
                            }
                        },
                        timeout,
                        TimeUnit.MILLISECONDS,
                    )
                try {
                    call.enqueue(
                        object : Callback {
                            override fun onFailure(call: Call, error: IOException) =
                                finish(id, entry, null, "http_failed")

                            override fun onResponse(call: Call, response: Response) {
                                try {
                                    val value =
                                        response.use {
                                            read(it, request.url, maximumResponseBytes.toInt())
                                        }
                                    finish(id, entry, value, null)
                                } catch (error: Exception) {
                                    finish(
                                        id,
                                        entry,
                                        null,
                                        (error as? NativeFailure)?.code ?: "http_failed",
                                    )
                                }
                            }
                        }
                    )
                } catch (_: Exception) {
                    finish(id, entry, null, "http_unavailable")
                }
            }
        } catch (error: Exception) {
            output.completeExceptionally(
                NativeFailure((error as? NativeFailure)?.code ?: "http_invalid_request")
            )
        }
        return output
    }

    private fun finish(
        id: String,
        entry: Exchange,
        response: FirstPartyHTTPResponse?,
        error: String?,
    ) {
        synchronized(lock) {
            if (active[id] !== entry) return
            active.remove(id)
            entry.timer?.cancel(false)
            if (nowNanos() - entry.deadline >= 0)
                entry.output.completeExceptionally(NativeFailure("http_failed"))
            else if (error != null) entry.output.completeExceptionally(NativeFailure(error))
            else entry.output.complete(response!!)
        }
    }

    fun cancel(id: String) {
        synchronized(lock) {
            if (!id.matches(Regex("[A-Za-z0-9_-]{43}")) || closed) return
            val entry = active[id]
            if (entry != null) {
                entry.output.completeExceptionally(NativeFailure("http_cancelled"))
                entry.call.cancel()
                return
            }
            pruneCancelled()
            val deadline = nowNanos() + TimeUnit.SECONDS.toNanos(120)
            if (cancelled.size >= 128) rejectUntil = deadline else cancelled[id] = deadline
        }
    }

    private fun pruneCancelled() {
        val now = nowNanos()
        cancelled.entries.removeAll { now - it.value >= 0 }
        if (rejectUntil?.let { now - it >= 0 } == true) rejectUntil = null
    }

    override fun close() {
        synchronized(lock) {
            closed = true
            active.values.forEach {
                it.output.completeExceptionally(NativeFailure("http_cancelled"))
                it.timer?.cancel(false)
                it.call.cancel()
            }
            cancelled.clear()
        }
        timer.shutdownNow()
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
    }

    companion object {
        private val forbidden =
            setOf(
                "host",
                "cookie",
                "cookie2",
                "connection",
                "transfer-encoding",
                "content-length",
                "proxy-authorization",
                "proxy-connection",
                "upgrade",
                "trailer",
                "te",
            )

        private fun utf8(value: String): ByteArray {
            val bytes =
                Charsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value))
            return ByteArray(bytes.remaining()).also { bytes.get(it) }
        }

        private fun request(
            id: String,
            url: String,
            method: String,
            headersJSON: String,
            body: String?,
            maximumBytes: Double,
            timeout: Double,
            allowLoopback: Boolean,
        ): Request {
            requireNative(
                id.matches(Regex("[A-Za-z0-9_-]{43}")) &&
                    utf8(url).size <= 8192 &&
                    method in setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS") &&
                    maximumBytes.isFinite() &&
                    maximumBytes in 1.0..1048576.0 &&
                    maximumBytes % 1 == 0.0 &&
                    timeout.isFinite() &&
                    timeout in 1000.0..120000.0 &&
                    timeout % 1 == 0.0 &&
                    utf8(headersJSON).size <= 32768 &&
                    !(body != null && method in setOf("GET", "HEAD")),
                "http_invalid_request",
            )
            val uri = URI(url)
            requireNative(
                uri.rawUserInfo == null &&
                    uri.rawFragment == null &&
                    uri.host != null &&
                    uri.port in -1..65535 &&
                    uri.port != 0 &&
                    (uri.scheme == "https" ||
                        (allowLoopback &&
                            uri.scheme == "http" &&
                            uri.host.lowercase(Locale.ROOT) in
                                setOf("localhost", "127.0.0.1", "::1", "[::1]"))),
                "http_invalid_request",
            )
            val ascii = URI(uri.toASCIIString())
            val expected =
                "${ascii.scheme}://${ascii.rawAuthority}${ascii.rawPath.ifEmpty { "/" }}" +
                    (ascii.rawQuery?.let { "?$it" } ?: "")
            val endpoint = url.toHttpUrl()
            // Reject a normalization that could change the DPoP htu target.
            requireNative(endpoint.toString() == expected, "http_invalid_request")
            // A header map is flat. Bound depth before parsing bridge-controlled
            // JSON, including objects hidden in values that will be rejected.
            var quoted = false
            var escaped = false
            var depth = 0
            headersJSON.forEach { c ->
                if (quoted) {
                    if (escaped) escaped = false
                    else if (c == '\\') escaped = true else if (c == '"') quoted = false
                } else
                    when (c) {
                        '"' -> quoted = true
                        '{' -> {
                            depth++
                            requireNative(depth == 1, "http_invalid_request")
                        }
                        '}' -> depth--
                        '[' -> throw NativeFailure("http_invalid_request")
                    }
            }
            val headers =
                Json.parseToJsonElement(headersJSON) as? JsonObject
                    ?: throw NativeFailure("http_invalid_request")
            val builder = Request.Builder().url(endpoint).tag(Attempt::class.java, Attempt())
            var headerBytes = 0
            val names = mutableSetOf<String>()
            for ((name, raw) in headers) {
                val primitive = raw as? JsonPrimitive
                requireNative(primitive?.isString == true, "http_invalid_request")
                val value = primitive!!.content
                val normalized = name.lowercase(Locale.ROOT)
                headerBytes += utf8(name).size + utf8(value).size
                requireNative(
                    headerBytes <= 16384 &&
                        normalized !in forbidden &&
                        names.add(normalized) &&
                        name.matches(Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+")) &&
                        value.none { it.code < 32 || it.code >= 127 },
                    "http_invalid_request",
                )
                builder.header(name, value)
            }
            val bytes = body?.let(::utf8)
            requireNative((bytes?.size ?: 0) <= 2097152, "http_invalid_request")
            val payload =
                if (bytes != null || method in setOf("POST", "PUT", "PATCH")) {
                    object : RequestBody() {
                        private val data = bytes ?: ByteArray(0)

                        override fun contentType(): MediaType? = null

                        override fun contentLength() = data.size.toLong()

                        override fun isOneShot() = true

                        override fun writeTo(sink: BufferedSink) {
                            sink.write(data)
                        }
                    }
                } else null
            return builder.method(method, payload).build()
        }

        private fun read(
            response: Response,
            expected: HttpUrl,
            maximum: Int,
        ): FirstPartyHTTPResponse {
            requireNative(response.code !in 300..399, "http_redirect_rejected")
            requireNative(
                response.request.url == expected &&
                    response.code in 100..599 &&
                    response.headers.sumOf { utf8(it.first).size + utf8(it.second).size } <= 16384,
                "http_invalid_response",
            )
            val body = response.body ?: throw NativeFailure("http_invalid_response")
            requireNative(body.contentLength() <= maximum, "http_response_too_large")
            val bytes = Buffer()
            val source = body.source()
            while (true) {
                val count = source.read(bytes, minOf(8192L, maximum.toLong() + 1 - bytes.size))
                if (count == -1L) break
                requireNative(bytes.size <= maximum, "http_response_too_large")
            }
            val text =
                try {
                    Charsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes.readByteArray()))
                        .toString()
                } catch (_: Exception) {
                    throw NativeFailure("http_invalid_response")
                }
            val headers = buildJsonObject {
                response.headers.names().forEach { name ->
                    val normalized = name.lowercase(Locale.ROOT)
                    if (normalized !in setOf("set-cookie", "set-cookie2"))
                        put(normalized, response.headers.values(name).joinToString(", "))
                }
            }
            return FirstPartyHTTPResponse(
                expected.toString(),
                response.code,
                headers.toString(),
                text,
            )
        }
    }
}
