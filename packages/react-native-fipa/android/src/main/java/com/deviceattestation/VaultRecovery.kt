package com.deviceattestation

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlinx.serialization.json.*

/**
 * Android's authority must distinguish proven loss from locked/unavailable storage. Neither
 * operation may touch DPoP or other application keys.
 */
internal enum class VaultKeyLoss {
    MISSING,
    INVALIDATED,
}

internal interface VaultRecoveryKeys {
    fun loss(): VaultKeyLoss?

    fun recover()
}

internal data class VaultRecoveryRequest(val token: String, val inProgress: Boolean)

internal data class VaultRecoveryMarker(
    val token: String,
    val phase: String,
    val preparedAt: Long,
    val epoch: Long = 0,
) {
    fun encode(): ByteArray =
        buildJsonObject {
                put("version", 1)
                put("token", token)
                put("phase", phase)
                put("preparedAt", preparedAt)
                put("epoch", epoch)
            }
            .toString()
            .toByteArray()

    companion object {
        // Disjoint exact-JavaScript-integer generations across recovery. Each
        // account gets 2^32 revisions per epoch; exhaustion fails closed.
        const val GENERATIONS_PER_EPOCH = 4294967296L
        const val MAX_EPOCH = VaultCodec.MAX_GENERATION / GENERATIONS_PER_EPOCH

        fun decode(bytes: ByteArray): VaultRecoveryMarker {
            try {
                requireNative(bytes.size <= 1024, "vault_corrupt")
                val text =
                    Charsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes))
                        .toString()
                val value = VaultCodec.objectJSON(text, 1024)
                requireNative(
                    value.keys == setOf("version", "token", "phase", "preparedAt", "epoch"),
                    "vault_corrupt",
                )
                fun string(name: String): String {
                    val p = value[name]!!.jsonPrimitive
                    requireNative(p.isString, "vault_corrupt")
                    return p.content
                }
                val token = string("token")
                val phase = string("phase")
                val time = value["preparedAt"]!!.jsonPrimitive
                val epoch = value["epoch"]!!.jsonPrimitive
                val version = value["version"]!!.jsonPrimitive
                requireNative(
                    !version.isString &&
                        version.content == "1" &&
                        !time.isString &&
                        time.content.matches(Regex("[1-9][0-9]{0,15}")) &&
                        time.longOrNull != null &&
                        token.matches(Regex("[A-Za-z0-9_-]{43}")) &&
                        !epoch.isString &&
                        epoch.longOrNull != null &&
                        epoch.long in 0..MAX_EPOCH &&
                        phase in setOf("prepared", "authorized", "complete", "cancelled"),
                    "vault_corrupt",
                )
                return VaultRecoveryMarker(token, phase, time.long, epoch.long).also {
                    // Only the canonical representation emitted by this library
                    // is accepted, including no duplicate or unknown fields.
                    requireNative(it.encode().contentEquals(bytes), "vault_corrupt")
                }
            } catch (_: Exception) {
                throw NativeFailure("vault_corrupt")
            }
        }
    }
}
