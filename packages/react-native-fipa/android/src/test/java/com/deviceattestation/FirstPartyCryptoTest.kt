package com.deviceattestation

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class FirstPartyCryptoTest {
    private fun key(curve: String = "secp256r1") =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec(curve)) }
            .generateKeyPair()

    private fun rejected(code: String, operation: () -> Unit) {
        try {
            operation()
            fail("Expected rejection")
        } catch (error: NativeFailure) {
            assertEquals(code, error.code)
        }
    }

    @Test
    fun hashesUtf8AndCanonicalDigests() {
        assertEquals(
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
            FirstPartyCrypto.sha256Utf8("abc"),
        )
        val tokens = (1..100).map { FirstPartyCrypto.randomToken() }
        assertEquals(100, tokens.toSet().size)
        tokens.forEach { assertEquals(32, FirstPartyCrypto.decodeDigest(it).size) }
        rejected("key_invalid_input") { FirstPartyCrypto.decodeDigest("A".repeat(42) + "B") }
        rejected("key_invalid_input") { FirstPartyCrypto.decodeDigest("A".repeat(43) + "=") }
        rejected("key_invalid_input") { FirstPartyCrypto.sha256Utf8("é".repeat(32769)) }
    }

    @Test
    fun quotesJsonWithoutChangingUnicodeOrSlashes() {
        assertEquals(
            "\"a\\\"b\\\\c\\u000ad\\u0000é/\"",
            FirstPartyCrypto.quote("a\"b\\c\nd\u0000é/"),
        )
    }

    @Test
    fun proofBindsKeyMethodUrlTokenAndNonce() {
        val pair = key()
        val public = pair.public as ECPublicKey
        val jkt = FirstPartyCrypto.thumbprint(public)
        assertEquals(43, jkt.length)
        assertEquals(FirstPartyCrypto.sha256Utf8(FirstPartyCrypto.publicJwk(public)), jkt)
        val input =
            FirstPartyCrypto.proofInput(
                public,
                jkt,
                "https://example.com:443/api/%2F?q=secret#fragment",
                "POST",
                "access-token",
                "a\"b",
                1700000000,
            )
        val pieces = input.split('.')
        val header = String(Base64.getUrlDecoder().decode(pieces[0]), Charsets.UTF_8)
        val claims = String(Base64.getUrlDecoder().decode(pieces[1]), Charsets.UTF_8)
        assertTrue(header.contains("\"alg\":\"ES256\""))
        assertTrue(header.contains("\"typ\":\"dpop+jwt\""))
        assertTrue(header.contains(FirstPartyCrypto.publicJwk(public)))
        assertTrue(claims.contains("\"htu\":\"https://example.com:443/api/%2F\""))
        assertTrue(claims.contains("\"htm\":\"POST\""))
        assertTrue(claims.contains("\"iat\":1700000000"))
        assertTrue(claims.contains("\"ath\":\"${FirstPartyCrypto.sha256Utf8("access-token")}\""))
        assertTrue(claims.contains("\"nonce\":\"a\\\"b\""))
        assertFalse(claims.contains("secret"))
        val der =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private)
                update(input.toByteArray())
                sign()
            }
        val jose = FirstPartyCrypto.joseSignature(der)
        assertEquals(64, jose.size)
        fun derInteger(raw: ByteArray): ByteArray {
            val value =
                raw.dropWhile { it == 0.toByte() }
                    .toByteArray()
                    .let { if (it[0].toInt() and 128 != 0) byteArrayOf(0) + it else it }
            return byteArrayOf(2, value.size.toByte()) + value
        }
        val values = derInteger(jose.copyOfRange(0, 32)) + derInteger(jose.copyOfRange(32, 64))
        assertTrue(
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(pair.public)
                update(input.toByteArray())
                verify(byteArrayOf(0x30, values.size.toByte()) + values)
            }
        )
    }

    @Test
    fun stripsQueryAndFragmentAndKeepsIpv6() {
        val public = key().public as ECPublicKey
        for ((url, expected) in
            mapOf(
                "https://example.com?x=1" to "https://example.com/",
                "https://[::1]:8443/path#fragment" to "https://[::1]:8443/path",
            )) {
            val input =
                FirstPartyCrypto.proofInput(
                    public,
                    FirstPartyCrypto.thumbprint(public),
                    url,
                    "GET",
                    null,
                    null,
                )
            val claims = String(Base64.getUrlDecoder().decode(input.split('.')[1]))
            assertTrue(claims.contains("\"htu\":\"$expected\""))
            assertFalse(claims.contains("\"ath\""))
            assertFalse(claims.contains("\"nonce\""))
        }
    }

    @Test
    fun refusesWrongKeysCurvesAndInvalidRequestInputs() {
        val public = key().public as ECPublicKey
        rejected("key_mismatch") {
            FirstPartyCrypto.proofInput(
                public,
                FirstPartyCrypto.thumbprint(key().public as ECPublicKey),
                "https://example.com",
                "GET",
                null,
                null,
            )
        }
        rejected("key_unavailable") {
            FirstPartyCrypto.publicJwk(key("secp384r1").public as ECPublicKey)
        }
        for (url in
            listOf(
                "https://user:password@example.com",
                "file:///a",
                "not a url",
                "https://example.com:70000",
                "https://example.com/" + "a".repeat(8192),
            )) rejected("key_invalid_input") {
            FirstPartyCrypto.proofInput(
                public,
                FirstPartyCrypto.thumbprint(public),
                url,
                "GET",
                null,
                null,
            )
        }
        rejected("key_invalid_input") {
            FirstPartyCrypto.proofInput(
                public,
                FirstPartyCrypto.thumbprint(public),
                "https://example.com",
                "get",
                null,
                null,
            )
        }
        rejected("key_invalid_input") {
            FirstPartyCrypto.proofInput(
                public,
                FirstPartyCrypto.thumbprint(public),
                "https://example.com",
                "GET",
                "x".repeat(16385),
                null,
            )
        }
        rejected("key_invalid_input") {
            FirstPartyCrypto.proofInput(
                public,
                FirstPartyCrypto.thumbprint(public),
                "https://example.com",
                "GET",
                null,
                "x".repeat(1025),
            )
        }
    }

    @Test
    fun convertsCanonicalDerIntegersWithPaddingAndRejectsMalformedSignatures() {
        val value = FirstPartyCrypto.joseSignature(byteArrayOf(0x30, 6, 2, 1, 1, 2, 1, 2))
        assertEquals(1, value[31].toInt())
        assertEquals(2, value[63].toInt())
        for (invalid in
            listOf(
                byteArrayOf(),
                byteArrayOf(0x30, 6, 2, 1, 0, 2, 1, 1),
                byteArrayOf(0x30, 6, 2, 1, 0x80.toByte(), 2, 1, 1),
                byteArrayOf(0x30, 7, 2, 2, 0, 1, 2, 1, 1),
                byteArrayOf(0x30, 6, 2, 33, 1, 2, 1, 1),
                byteArrayOf(0x30, 7, 2, 1, 1, 2, 1, 1, 0),
            )) rejected("key_failed") { FirstPartyCrypto.joseSignature(invalid) }
    }
}
