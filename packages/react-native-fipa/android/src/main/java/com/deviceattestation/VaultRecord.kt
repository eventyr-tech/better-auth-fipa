package com.deviceattestation

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import kotlinx.serialization.json.*

internal data class VaultLease(val id: String, var expiresAt: Long, val preserveSession: Boolean)

internal data class VaultRecord(
    val account: String,
    val accessibility: String = "when-unlocked",
    var generation: Long = 0,
    var identityJSON: String? = null,
    var sessionJSON: String? = null,
    var recoverySessionJSON: String? = null,
    var rollbackSessionJSON: String? = null,
    var hasInteraction: Boolean = false,
    var recoveryRequired: Boolean = false,
    var lease: VaultLease? = null,
)

internal object VaultCodec {
    const val MAX_GENERATION = 9007199254740991L
    const val MAX_RECORD_BYTES = 524288
    private val jsonNumber = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")

    private fun strictPrimitives(value: JsonElement) {
        when (value) {
            is JsonObject -> value.values.forEach(::strictPrimitives)
            is JsonArray -> value.forEach(::strictPrimitives)
            is JsonPrimitive ->
                if (
                    !value.isString &&
                        value !== JsonNull &&
                        value.content !in listOf("true", "false") &&
                        !jsonNumber.matches(value.content)
                )
                    bad()
        }
    }

    private fun bad(): Nothing = throw NativeFailure("vault_corrupt")

    fun account(namespace: String, slot: String): String {
        requireNative(
            namespace.isNotEmpty() &&
                namespace.toByteArray().size <= 4096 &&
                slot.isNotEmpty() &&
                slot.toByteArray().size <= 256,
            "vault_invalid_input",
        )
        val value =
            JsonArray(
                    listOf("device-attestation-vault/android/v1", namespace, slot)
                        .map(::JsonPrimitive)
                )
                .toString()
        return MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") {
            "%02x".format(it)
        }
    }

    fun policy(value: String) {
        requireNative(value == "when-unlocked", "vault_policy_mismatch")
    }

    fun generation(value: Double): Long {
        requireNative(
            value.isFinite() && value >= 0 && value <= MAX_GENERATION && value % 1.0 == 0.0,
            "vault_invalid_input",
        )
        return value.toLong()
    }

    fun duration(value: Double): Long {
        requireNative(
            value.isFinite() && value in 5000.0..120000.0 && value % 1.0 == 0.0,
            "vault_invalid_input",
        )
        return value.toLong()
    }

    fun validateJSON(value: String?, limit: Int) {
        if (value == null) return
        try {
            objectJSON(value, limit)
        } catch (_: Exception) {
            throw NativeFailure("vault_invalid_input")
        }
    }

    internal fun objectJSON(value: String, limit: Int): JsonObject {
        if (value.toByteArray().size > limit) bad()
        // Bound recursion before entering the JSON parser, including opaque
        // session/identity documents supplied by the bridge.
        var depth = 0
        var quoted = false
        var escaped = false
        value.forEach { c ->
            if (c.code < 32 && (quoted || c !in listOf('\t', '\r', '\n'))) bad()
            if (quoted) {
                if (escaped) escaped = false
                else if (c == '\\') escaped = true else if (c == '"') quoted = false
            } else
                when (c) {
                    '"' -> quoted = true
                    '{',
                    '[' -> {
                        depth++
                        if (depth > 64) bad()
                    }
                    '}',
                    ']' -> {
                        depth--
                        if (depth < 0) bad()
                    }
                }
        }
        if (depth != 0 || quoted) bad()
        return (Json.parseToJsonElement(value) as? JsonObject ?: bad()).also(::strictPrimitives)
    }

    private fun string(value: JsonElement?): String =
        (value as? JsonPrimitive)?.let { if (it.isString) it.content else null } ?: bad()

    private fun nullable(value: JsonElement?): String? =
        if (value === JsonNull) null else string(value)

    private fun integer(value: JsonElement?): Long =
        (value as? JsonPrimitive)?.let { if (!it.isString) it.longOrNull else null } ?: bad()

    private fun boolean(value: JsonElement?): Boolean =
        (value as? JsonPrimitive)?.let { if (!it.isString) it.booleanOrNull else null } ?: bad()

    fun decode(bytes: ByteArray, account: String): VaultRecord {
        try {
            if (bytes.size > MAX_RECORD_BYTES) bad()
            val text =
                Charsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString()
            val obj = objectJSON(text, MAX_RECORD_BYTES)
            if (
                obj.keys !=
                    setOf(
                        "version",
                        "account",
                        "accessibility",
                        "generation",
                        "identityJSON",
                        "sessionJSON",
                        "recoverySessionJSON",
                        "rollbackSessionJSON",
                        "hasInteraction",
                        "recoveryRequired",
                        "lease",
                    )
            )
                bad()
            if (integer(obj["version"]) != 1L || string(obj["account"]) != account) bad()
            val record =
                VaultRecord(
                    account,
                    string(obj["accessibility"]),
                    integer(obj["generation"]),
                    nullable(obj["identityJSON"]),
                    nullable(obj["sessionJSON"]),
                    nullable(obj["recoverySessionJSON"]),
                    nullable(obj["rollbackSessionJSON"]),
                    boolean(obj["hasInteraction"]),
                    boolean(obj["recoveryRequired"]),
                )
            if (record.generation !in 0..MAX_GENERATION || record.accessibility != "when-unlocked")
                bad()
            if (obj["lease"] !== JsonNull) {
                val lease = obj["lease"] as? JsonObject ?: bad()
                if (lease.keys != setOf("id", "expiresAt", "preserveSession")) bad()
                val id = string(lease["id"])
                FirstPartyCrypto.decodeDigest(id)
                val expiresAt = integer(lease["expiresAt"])
                if (expiresAt <= 0) bad()
                record.lease = VaultLease(id, expiresAt, boolean(lease["preserveSession"]))
            }
            validateJSON(record.identityJSON, 8192)
            listOf(record.sessionJSON, record.recoverySessionJSON, record.rollbackSessionJSON)
                .forEach { validateJSON(it, 65536) }
            return record
        } catch (_: Exception) {
            bad()
        }
    }

    fun encode(record: VaultRecord): ByteArray {
        val obj = buildJsonObject {
            put("version", 1)
            put("account", record.account)
            put("accessibility", record.accessibility)
            put("generation", record.generation)
            put("identityJSON", record.identityJSON?.let(::JsonPrimitive) ?: JsonNull)
            put("sessionJSON", record.sessionJSON?.let(::JsonPrimitive) ?: JsonNull)
            put("recoverySessionJSON", record.recoverySessionJSON?.let(::JsonPrimitive) ?: JsonNull)
            put("rollbackSessionJSON", record.rollbackSessionJSON?.let(::JsonPrimitive) ?: JsonNull)
            put("hasInteraction", record.hasInteraction)
            put("recoveryRequired", record.recoveryRequired)
            put(
                "lease",
                record.lease?.let { lease ->
                    buildJsonObject {
                        put("id", lease.id)
                        put("expiresAt", lease.expiresAt)
                        put("preserveSession", lease.preserveSession)
                    }
                } ?: JsonNull,
            )
        }
        return obj.toString().toByteArray().also {
            requireNative(it.size <= MAX_RECORD_BYTES, "vault_invalid_input")
        }
    }
}
