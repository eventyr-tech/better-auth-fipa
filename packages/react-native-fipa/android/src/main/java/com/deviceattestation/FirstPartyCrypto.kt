package com.deviceattestation

import java.math.BigInteger
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.util.Base64

/** Pure encodings, shared by production Keystore signing and JVM crypto tests. */
internal object FirstPartyCrypto {
    private val random = SecureRandom()

    fun encode(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    fun digest(value: ByteArray): String =
        encode(MessageDigest.getInstance("SHA-256").digest(value))

    fun sha256Utf8(value: String): String {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        requireNative(bytes.size <= 65536)
        return digest(bytes)
    }

    fun randomToken(): String = encode(ByteArray(32).also(random::nextBytes))

    fun decodeDigest(value: String): ByteArray {
        requireNative(value.matches(Regex("[A-Za-z0-9_-]{43}")))
        val decoded =
            try {
                Base64.getUrlDecoder().decode(value)
            } catch (_: IllegalArgumentException) {
                throw NativeFailure("key_invalid_input")
            }
        requireNative(decoded.size == 32 && encode(decoded) == value)
        return decoded
    }

    fun quote(value: String): String = buildString {
        append('"')
        value.forEach { c ->
            when (c) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                else ->
                    if (c.code < 32) append("\\u" + c.code.toString(16).padStart(4, '0'))
                    else append(c)
            }
        }
        append('"')
    }

    fun publicJwk(key: ECPublicKey): String {
        val parameters =
            AlgorithmParameters.getInstance("EC")
                .apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
        requireNative(
            key.params.curve == parameters.curve &&
                key.params.generator == parameters.generator &&
                key.params.order == parameters.order &&
                key.params.cofactor == parameters.cofactor,
            "key_unavailable",
        )
        fun coordinate(n: BigInteger): String {
            requireNative(n.signum() >= 0 && n.bitLength() <= 256, "key_unavailable")
            val raw =
                n.toByteArray().let {
                    if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it
                }
            return encode(ByteArray(32 - raw.size) + raw)
        }
        return "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":" +
            quote(coordinate(key.w.affineX)) +
            ",\"y\":" +
            quote(coordinate(key.w.affineY)) +
            "}"
    }

    fun thumbprint(key: ECPublicKey): String = sha256Utf8(publicJwk(key))

    fun proofInput(
        key: ECPublicKey,
        expectedThumbprint: String,
        url: String,
        method: String,
        accessToken: String?,
        nonce: String?,
        nowSeconds: Long = System.currentTimeMillis() / 1000,
    ): String {
        decodeDigest(expectedThumbprint)
        requireNative(thumbprint(key) == expectedThumbprint, "key_mismatch")
        requireNative(
            url.toByteArray().size <= 8192 &&
                method.matches(Regex("[A-Z]{1,16}")) &&
                (accessToken?.toByteArray()?.size ?: 0) <= 16384 &&
                (nonce?.toByteArray()?.size ?: 0) <= 1024 &&
                nowSeconds > 0
        )
        val uri =
            try {
                URI(url)
            } catch (_: Exception) {
                throw NativeFailure("key_invalid_input")
            }
        requireNative(
            uri.scheme in listOf("https", "http") &&
                uri.host != null &&
                uri.rawUserInfo == null &&
                uri.port in -1..65535
        )
        val ascii = URI(uri.toASCIIString())
        val htu = "${ascii.scheme}://${ascii.rawAuthority}${ascii.rawPath.ifEmpty { "/" }}"
        val header = "{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\",\"jwk\":" + publicJwk(key) + "}"
        val payload = buildString {
            append(
                "{\"htu\":${quote(htu)},\"htm\":${quote(method)},\"iat\":$nowSeconds,\"jti\":${quote(randomToken())}"
            )
            if (accessToken != null) append(",\"ath\":${quote(sha256Utf8(accessToken))}")
            if (nonce != null) append(",\"nonce\":${quote(nonce)}")
            append('}')
        }
        return encode(header.toByteArray(StandardCharsets.UTF_8)) +
            "." +
            encode(payload.toByteArray(StandardCharsets.UTF_8))
    }

    /** ES256 JWS signatures are fixed-width r||s, not ASN.1 DER. */
    fun joseSignature(der: ByteArray): ByteArray {
        fun bad(): Nothing = throw NativeFailure("key_failed")
        if (der.size !in 8..72 || der[0] != 0x30.toByte() || der[1].toInt() != der.size - 2) bad()
        var offset = 2
        fun integer(): ByteArray {
            if (offset + 2 > der.size || der[offset++] != 2.toByte()) bad()
            val size = der[offset++].toInt() and 255
            if (size !in 1..33 || offset + size > der.size) bad()
            var bytes = der.copyOfRange(offset, offset + size)
            offset += size
            if (bytes[0].toInt() and 128 != 0) bad()
            if (bytes.size > 1 && bytes[0] == 0.toByte()) {
                if (bytes[1].toInt() and 128 == 0) bad()
                bytes = bytes.copyOfRange(1, bytes.size)
            }
            if (bytes.size > 32 || bytes.all { it == 0.toByte() }) bad()
            return ByteArray(32 - bytes.size) + bytes
        }
        val raw = integer() + integer()
        if (offset != der.size) bad()
        return raw
    }
}
