package com.deviceattestation

import org.junit.Assert.*
import org.junit.Test

internal class MemoryVaultStorage : SessionVaultStorage {
    val records = mutableMapOf<String, ByteArray>()
    var readError: String? = null
    var writeError: String? = null

    @Synchronized
    override fun <T> transaction(account: String, operation: (VaultSlotStorage) -> T): T =
        operation(
            object : VaultSlotStorage {
                override fun read(): ByteArray? {
                    readError?.let { throw NativeFailure(it) }
                    return records[account]?.clone()
                }

                override fun write(bytes: ByteArray) {
                    writeError?.let { throw NativeFailure(it) }
                    records[account] = bytes.clone()
                }
            }
        )
}

class SessionVaultTest {
    private val store = MemoryVaultStorage()
    private var now = 1000000L
    private val identity = "{\"alias\":\"retained\"}"
    private val session = "{\"refreshToken\":\"secret\"}"

    private fun vault() = SessionVault(store, { now })

    private fun acquire(
        vault: SessionVault = vault(),
        preserve: Boolean = false,
        slot: String = "slot",
    ) = vault.acquire("issuer|client", slot, "when-unlocked", 30000.0, preserve)

    private fun commit(
        vault: SessionVault,
        held: VaultSnapshot,
        session: String? = this.session,
        recoverable: String? = null,
        interaction: Boolean = false,
    ) =
        vault.commit(
            "issuer|client",
            "slot",
            held.leaseId,
            held.generation.toDouble(),
            identity,
            session,
            recoverable,
            interaction,
        )

    private fun rejected(code: String, operation: () -> Unit) {
        try {
            operation()
            fail("Expected rejection")
        } catch (error: NativeFailure) {
            assertEquals(code, error.code)
        }
    }

    private fun seed(vault: SessionVault) {
        commit(vault, acquire(vault), recoverable = session)
    }

    @Test
    fun commitsAtomicallyAndConsumesLeaseAcrossInstances() {
        val first = vault()
        val held = acquire(first)
        rejected("vault_busy") { acquire() }
        assertEquals(1L, commit(first, held))
        rejected("vault_lost_lease") { commit(first, held) }
        val restored = acquire()
        assertEquals(identity, restored.identityJSON)
        assertEquals(session, restored.sessionJSON)
        assertEquals(1L, restored.generation)
        assertFalse(restored.recoveryRequired)
        rejected("vault_lost_lease") {
            first.renew("issuer|client", "slot", held.leaseId, held.generation.toDouble(), 30000.0)
        }
    }

    @Test
    fun expiryAndAbandonDropConsumedRefreshButKeepIdentity() {
        for (expired in listOf(false, true)) {
            store.records.clear()
            val instance = vault()
            seed(instance)
            val held = acquire(instance)
            if (expired) now += 31000
            else instance.abandon("issuer|client", "slot", held.leaseId, held.generation.toDouble())
            val recovered = acquire()
            assertEquals(identity, recovered.identityJSON)
            assertNull(recovered.sessionJSON)
            assertTrue(recovered.recoveryRequired)
            rejected("vault_lost_lease") { commit(instance, held) }
        }
    }

    @Test
    fun interactionFailureRecoversOnlyIndependentCommittedSession() {
        for (expired in listOf(false, true)) {
            store.records.clear()
            val instance = vault()
            seed(instance)
            val held = acquire(instance, true)
            if (expired) now += 31000
            else instance.abandon("issuer|client", "slot", held.leaseId, held.generation.toDouble())
            val recovered = acquire()
            assertEquals(session, recovered.sessionJSON)
            assertTrue(recovered.recoveryRequired)
            rejected("vault_lost_lease") { commit(instance, held) }
        }
    }

    @Test
    fun cancellationPreemptsInteractionAndFencesLateResult() {
        val instance = vault()
        seed(instance)
        val held = acquire(instance, true)
        val cancelled = instance.cancelInteraction("issuer|client", "slot", "when-unlocked")
        assertTrue(cancelled.cancelled)
        assertEquals(session, cancelled.sessionJSON)
        rejected("vault_lost_lease") { commit(instance, held) }
        assertEquals(session, acquire().sessionJSON)
    }

    @Test
    fun cancellationDoesNotRestoreATokenDuringRefresh() {
        val instance = vault()
        seed(instance)
        acquire(instance)
        rejected("vault_busy") {
            instance.cancelInteraction("issuer|client", "slot", "when-unlocked")
        }
        now += 31000
        assertTrue(instance.cancelInteraction("issuer|client", "slot", "when-unlocked").cancelled)
        assertNull(acquire().sessionJSON)
    }

    @Test
    fun committedInteractionCancellationPreservesPriorSession() {
        val instance = vault()
        seed(instance)
        assertFalse(instance.cancelInteraction("issuer|client", "slot", "when-unlocked").cancelled)
        commit(instance, acquire(instance, true), "{\"step\":\"pending\"}", session, true)
        val cancelled = instance.cancelInteraction("issuer|client", "slot", "when-unlocked")
        assertTrue(cancelled.cancelled)
        assertEquals("{\"step\":\"pending\"}", cancelled.sessionJSON)
        assertEquals(session, acquire().sessionJSON)
    }

    @Test
    fun compensationCannotEraseALaterCommittedLogin() {
        val instance = vault()
        seed(instance)
        val commitGeneration =
            commit(
                instance,
                acquire(instance, true),
                "{\"refreshToken\":\"new\"}",
                "{\"refreshToken\":\"new\"}",
            )
        assertTrue(instance.discard("issuer|client", "slot", commitGeneration.toDouble()))
        val restored = acquire()
        assertEquals(session, restored.sessionJSON)
        val later = commit(instance, restored, "{\"refreshToken\":\"later\"}")
        assertFalse(instance.discard("issuer|client", "slot", commitGeneration.toDouble()))
        assertEquals(later, acquire().generation)
    }

    @Test
    fun logoutRemovesAllCapabilitiesBeforeReleasingLease() {
        val instance = vault()
        seed(instance)
        val held = acquire(instance)
        instance.clearSession("issuer|client", "slot", held.leaseId, held.generation.toDouble())
        rejected("vault_busy") { acquire() }
        instance.release("issuer|client", "slot", held.leaseId, held.generation.toDouble())
        val next = acquire()
        assertNull(next.sessionJSON)
        assertEquals(identity, next.identityJSON)
        val record =
            VaultCodec.decode(
                store.records.values.single(),
                VaultCodec.account("issuer|client", "slot"),
            )
        assertNull(record.recoverySessionJSON)
        assertNull(record.rollbackSessionJSON)
    }

    @Test
    fun identityJournalSurvivesCrashAndCannotBeWrittenByOldOwner() {
        val instance = vault()
        val held = acquire(instance)
        instance.saveIdentity(
            "issuer|client",
            "slot",
            held.leaseId,
            held.generation.toDouble(),
            identity,
        )
        now += 31000
        assertEquals(identity, acquire().identityJSON)
        rejected("vault_lost_lease") {
            instance.saveIdentity(
                "issuer|client",
                "slot",
                held.leaseId,
                held.generation.toDouble(),
                "{}",
            )
        }
    }

    @Test
    fun invalidationPreemptsLateCommitAndLeavesIdentity() {
        val instance = vault()
        seed(instance)
        val held = acquire(instance)
        val generation = instance.invalidate("issuer|client", "slot", "when-unlocked")
        assertTrue(generation > held.generation)
        rejected("vault_lost_lease") { commit(instance, held) }
        assertEquals(identity, acquire().identityJSON)
    }

    @Test
    fun renewExtendsOnlyTheCurrentLiveLease() {
        val instance = vault()
        val held = acquire(instance)
        now += 20000
        instance.renew("issuer|client", "slot", held.leaseId, held.generation.toDouble(), 30000.0)
        now += 20000
        rejected("vault_busy") { acquire() }
        instance.release("issuer|client", "slot", held.leaseId, held.generation.toDouble())
        rejected("vault_lost_lease") {
            instance.renew(
                "issuer|client",
                "slot",
                held.leaseId,
                held.generation.toDouble(),
                30000.0,
            )
        }
    }

    @Test
    fun storageErrorsNeverBecomeAnEmptyVaultOrSuccessfulCommit() {
        val instance = vault()
        val held = acquire(instance)
        store.writeError = "vault_locked"
        rejected("vault_locked") { commit(instance, held) }
        store.writeError = null
        rejected("vault_busy") { acquire() }
        commit(instance, held)
        store.readError = "vault_unavailable"
        rejected("vault_unavailable") { acquire() }
    }

    @Test
    fun separatesNamespacedSlotsAndValidatesInput() {
        val instance = vault()
        acquire(instance)
        acquire(instance, slot = "second")
        instance.acquire("other-issuer", "slot", "when-unlocked", 30000.0, false)
        assertEquals(3, store.records.size)
        for (duration in
            listOf(Double.NaN, Double.POSITIVE_INFINITY, 4999.0, 120001.0, 5000.5)) rejected(
            "vault_invalid_input"
        ) {
            instance.acquire("issuer", "slot", "when-unlocked", duration, false)
        }
        rejected("vault_policy_mismatch") {
            instance.acquire("issuer", "slot", "after-first-unlock", 30000.0, false)
        }
        rejected("vault_invalid_input") { instance.invalidate("", "slot", "when-unlocked") }
        for (generation in listOf(-1.0, 0.5, Double.NaN, 9007199254740992.0)) rejected(
            "vault_invalid_input"
        ) {
            instance.discard("issuer", "slot", generation)
        }
        assertFalse(instance.discard("absent", "slot", 0.0))
        assertFalse(instance.cancelInteraction("absent", "slot", "when-unlocked").cancelled)
    }

    @Test
    fun rejectsMalformedDeepOrOversizedJsonBeforeWriting() {
        val instance = vault()
        val held = acquire(instance)
        for (json in
            listOf(
                "[]",
                "null",
                "not-json",
                "{'a':1}",
                "{\"a\":NaN}",
                "{\"a\":" + "[".repeat(65) + "0" + "]".repeat(65) + "}",
                "{\"a\":\"" + "x".repeat(8192) + "\"}",
            )) rejected("vault_invalid_input") {
            instance.saveIdentity(
                "issuer|client",
                "slot",
                held.leaseId,
                held.generation.toDouble(),
                json,
            )
        }
        instance.saveIdentity(
            "issuer|client",
            "slot",
            held.leaseId,
            held.generation.toDouble(),
            "{\"escaped\":\"{[\\\"\"}",
        )
    }

    @Test
    fun rejectsCorruptRecordsAndGenerationExhaustion() {
        val account = VaultCodec.account("issuer|client", "slot")
        for (bytes in
            listOf(
                byteArrayOf(0xff.toByte()),
                "{}".toByteArray(),
                ByteArray(VaultCodec.MAX_RECORD_BYTES + 1),
            )) {
            store.records[account] = bytes
            rejected("vault_corrupt") { acquire() }
        }
        store.records[account] =
            VaultCodec.encode(VaultRecord(account, generation = VaultCodec.MAX_GENERATION))
        val instance = vault()
        val held = acquire(instance)
        rejected("vault_corrupt") { commit(instance, held) }
        rejected("vault_corrupt") { instance.invalidate("issuer|client", "slot", "when-unlocked") }
        store.records[account] = VaultCodec.encode(VaultRecord("other"))
        rejected("vault_corrupt") { acquire() }
    }
}
