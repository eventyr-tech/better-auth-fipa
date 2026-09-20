package com.deviceattestation

/**
 * Storage owns a lock spanning the entire read/modify/write transaction, across module instances
 * and processes. Network and signing are never performed here.
 */
internal interface VaultSlotStorage {
    val generationFloor: Long
        get() = 0

    val generationCeiling: Long
        get() = VaultCodec.MAX_GENERATION

    fun read(): ByteArray?

    fun write(bytes: ByteArray)
}

internal interface SessionVaultStorage {
    fun <T> transaction(account: String, operation: (VaultSlotStorage) -> T): T
}

internal data class VaultSnapshot(
    val leaseId: String,
    val generation: Long,
    val identityJSON: String?,
    val sessionJSON: String?,
    val recoveryRequired: Boolean,
)

internal data class CancelledInteraction(val sessionJSON: String?, val cancelled: Boolean)

internal class SessionVault(
    private val storage: SessionVaultStorage,
    private val now: () -> Long = System::currentTimeMillis,
    private val random: () -> String = FirstPartyCrypto::randomToken,
) {
    private fun successor(value: Long): Long {
        requireNative(value < VaultCodec.MAX_GENERATION, "vault_corrupt")
        return value + 1
    }

    private fun invalidate(record: VaultRecord, recover: Boolean = false) {
        record.generation = successor(record.generation)
        record.sessionJSON = if (recover) record.recoverySessionJSON else null
        record.recoverySessionJSON = record.sessionJSON
        record.rollbackSessionJSON = null
        record.hasInteraction = false
        record.recoveryRequired = true
        record.lease = null
    }

    private fun read(slot: VaultSlotStorage, account: String): VaultRecord? =
        slot.read()?.let {
            VaultCodec.decode(it, account).also { record ->
                requireNative(
                    record.generation in slot.generationFloor..slot.generationCeiling,
                    "vault_corrupt",
                )
            }
        }

    private fun write(slot: VaultSlotStorage, record: VaultRecord) {
        requireNative(
            record.generation in slot.generationFloor..slot.generationCeiling,
            "vault_corrupt",
        )
        slot.write(VaultCodec.encode(record))
    }

    private fun owned(
        slot: VaultSlotStorage,
        account: String,
        id: String,
        generation: Long,
    ): VaultRecord {
        val record = read(slot, account)
        requireNative(
            record != null &&
                record.generation == generation &&
                record.lease?.id == id &&
                record.lease!!.expiresAt > now(),
            "vault_lost_lease",
        )
        return record!!
    }

    fun acquire(
        namespace: String,
        slotId: String,
        accessibility: String,
        leaseMilliseconds: Double,
        preserveSession: Boolean,
    ): VaultSnapshot {
        val account = VaultCodec.account(namespace, slotId)
        VaultCodec.policy(accessibility)
        val duration = VaultCodec.duration(leaseMilliseconds)
        return storage.transaction(account) { slot ->
            val record =
                read(slot, account) ?: VaultRecord(account, generation = slot.generationFloor)
            record.lease?.let {
                requireNative(it.expiresAt <= now(), "vault_busy")
                invalidate(record, it.preserveSession)
            }
            val id = random()
            FirstPartyCrypto.decodeDigest(id)
            record.lease = VaultLease(id, now() + duration, preserveSession)
            write(slot, record)
            VaultSnapshot(
                id,
                record.generation,
                record.identityJSON,
                record.sessionJSON,
                record.recoveryRequired,
            )
        }
    }

    private fun <T> mutate(
        namespace: String,
        slotId: String,
        id: String,
        generation: Double,
        operation: (VaultRecord) -> T,
    ): T {
        val account = VaultCodec.account(namespace, slotId)
        val expected = VaultCodec.generation(generation)
        return storage.transaction(account) { slot ->
            val record = owned(slot, account, id, expected)
            val result = operation(record)
            write(slot, record)
            result
        }
    }

    fun commit(
        namespace: String,
        slotId: String,
        leaseId: String,
        generation: Double,
        identityJSON: String?,
        sessionJSON: String?,
        recoverySessionJSON: String?,
        hasInteraction: Boolean,
    ): Long {
        VaultCodec.validateJSON(identityJSON, 8192)
        VaultCodec.validateJSON(sessionJSON, 65536)
        VaultCodec.validateJSON(recoverySessionJSON, 65536)
        return mutate(namespace, slotId, leaseId, generation) { record ->
            record.generation = successor(record.generation)
            record.rollbackSessionJSON =
                if (record.lease!!.preserveSession) record.recoverySessionJSON else null
            record.identityJSON = identityJSON
            record.sessionJSON = sessionJSON
            record.recoverySessionJSON = recoverySessionJSON
            record.hasInteraction = hasInteraction
            record.recoveryRequired = false
            record.lease = null
            record.generation
        }
    }

    fun renew(
        namespace: String,
        slot: String,
        id: String,
        generation: Double,
        leaseMilliseconds: Double,
    ) {
        val duration = VaultCodec.duration(leaseMilliseconds)
        mutate(namespace, slot, id, generation) { it.lease!!.expiresAt = now() + duration }
    }

    fun release(namespace: String, slot: String, id: String, generation: Double) {
        mutate(namespace, slot, id, generation) {
            it.generation = successor(it.generation)
            it.lease = null
        }
    }

    fun saveIdentity(
        namespace: String,
        slot: String,
        id: String,
        generation: Double,
        identity: String,
    ) {
        VaultCodec.validateJSON(identity, 8192)
        mutate(namespace, slot, id, generation) { it.identityJSON = identity }
    }

    fun clearSession(namespace: String, slot: String, id: String, generation: Double) {
        mutate(namespace, slot, id, generation) {
            it.sessionJSON = null
            it.recoverySessionJSON = null
            it.rollbackSessionJSON = null
            it.hasInteraction = false
        }
    }

    fun abandon(namespace: String, slot: String, id: String, generation: Double): Long =
        mutate(namespace, slot, id, generation) {
            invalidate(it, it.lease!!.preserveSession)
            it.generation
        }

    fun invalidate(namespace: String, slotId: String, accessibility: String): Long {
        val account = VaultCodec.account(namespace, slotId)
        VaultCodec.policy(accessibility)
        return storage.transaction(account) { slot ->
            val record =
                read(slot, account) ?: VaultRecord(account, generation = slot.generationFloor)
            invalidate(record)
            write(slot, record)
            record.generation
        }
    }

    fun cancelInteraction(
        namespace: String,
        slotId: String,
        accessibility: String,
    ): CancelledInteraction {
        val account = VaultCodec.account(namespace, slotId)
        VaultCodec.policy(accessibility)
        return storage.transaction(account) { slot ->
            val record = read(slot, account) ?: return@transaction CancelledInteraction(null, false)
            val lease = record.lease
            requireNative(
                lease == null || lease.expiresAt <= now() || lease.preserveSession,
                "vault_busy",
            )
            if (lease == null && !record.hasInteraction)
                return@transaction CancelledInteraction(null, false)
            val previous = record.sessionJSON
            invalidate(record, lease == null || lease.preserveSession)
            write(slot, record)
            CancelledInteraction(previous, true)
        }
    }

    fun discard(namespace: String, slotId: String, generation: Double): Boolean {
        val account = VaultCodec.account(namespace, slotId)
        val expected = VaultCodec.generation(generation)
        return storage.transaction(account) { slot ->
            val record = read(slot, account) ?: return@transaction false
            if (record.generation != expected) return@transaction false
            record.recoverySessionJSON = record.rollbackSessionJSON
            invalidate(record, true)
            write(slot, record)
            true
        }
    }
}
