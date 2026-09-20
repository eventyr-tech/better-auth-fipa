package com.deviceattestation

import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

/**
 * Real ciphertext/journal/fsync tests. Software AES is a test-only authority; Android Keystore loss
 * and lock behavior still require signed device evidence.
 */
class VaultRecoveryTest {
    private val root = Files.createTempDirectory("vault-recovery-test-").toFile()
    private val directory = File(root, "vault")
    private var key: SecretKey? = null
    private var locked = false
    private var uncertain = false
    private var time = 1000000L
    private var recoveries = 0
    private var invalidatedKey = false
    private var checkpoint: (String) -> Unit = {}
    private var failSync = false

    private fun newKey() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    private fun storage() =
        EncryptedVaultStorage(
            directory,
            { create ->
                if (key == null) {
                    requireNative(create, "vault_key_lost")
                    key = newKey()
                }
                key!!
            },
            { requireNative(!locked, "vault_locked") },
            { file ->
                if (failSync) throw java.io.IOException("injected fsync failure")
                FileChannel.open(file.toPath(), StandardOpenOption.READ).use { it.force(true) }
            },
            { _, _ -> },
            recoveryKeys =
                object : VaultRecoveryKeys {
                    override fun loss(): VaultKeyLoss? {
                        requireNative(!uncertain, "vault_unavailable")
                        return if (key == null) VaultKeyLoss.MISSING
                        else if (invalidatedKey) VaultKeyLoss.INVALIDATED else null
                    }

                    override fun recover() {
                        requireNative(!uncertain, "vault_unavailable")
                        if (key == null || invalidatedKey) {
                            invalidatedKey = false
                            key = newKey()
                            recoveries++
                        }
                    }
                },
            now = { time },
            recoveryCheckpoint = { checkpoint(it) },
        )

    private val a = VaultCodec.account("issuer-a", "slot-a")
    private val b = VaultCodec.account("issuer-b", "slot-b")

    private fun write(account: String = a, text: String = "private-refresh-token") =
        storage().transaction(account) { it.write(text.toByteArray()) }

    private fun read(account: String = a): String? =
        storage().transaction(account) { it.read()?.toString(Charsets.UTF_8) }

    private fun records() = directory.listFiles()!!.filter { it.extension == "vault" }

    private fun lost(): VaultRecoveryRequest {
        write(a)
        write(b)
        key = null
        return storage().prepareRecovery()!!
    }

    private fun rejected(code: String, block: () -> Unit) {
        try {
            block()
            fail("Expected rejection")
        } catch (e: NativeFailure) {
            assertEquals(code, e.code)
        }
    }

    @After
    fun cleanup() {
        root.deleteRecursively()
    }

    @Test
    fun preparationIsNonDestructiveAndConfirmationClearsEveryNamespace() {
        val signingKey = File(root, "unrelated-signing-key").apply { writeText("retained") }
        val ticket = lost()
        val before = records().associate { it.name to it.readBytes().toList() }
        assertFalse(ticket.inProgress)
        assertEquals(ticket, storage().prepareRecovery())
        assertEquals(before, records().associate { it.name to it.readBytes().toList() })
        assertNull(key)
        rejected("vault_key_lost") { read() }
        assertFalse(storage().recover(ticket.token))
        assertTrue(storage().recover(ticket.token))
        assertEquals(1, recoveries)
        assertNull(read(a))
        assertNull(read(b))
        assertEquals("retained", signingKey.readText())
        write(text = "fresh-login")
        assertTrue(storage().recover(ticket.token))
        assertEquals("fresh-login", read())
        assertNull(storage().prepareRecovery())
    }

    @Test
    fun healthyEmptyLockedAndUncertainStorageNeverAuthorizeDeletion() {
        assertNull(storage().prepareRecovery())
        write()
        assertNull(storage().prepareRecovery())
        key = null
        locked = true
        rejected("vault_locked") { storage().prepareRecovery() }
        locked = false
        uncertain = true
        rejected("vault_unavailable") { storage().prepareRecovery() }
        assertEquals(1, records().size)
        assertEquals(
            "cancelled",
            VaultRecoveryMarker.decode(File(directory, ".recovery").readBytes()).phase,
        )
        assertEquals(0, recoveries)
    }

    @Test
    fun wrongExpiredAndReplacedTicketsCannotClearData() {
        val old = lost()
        rejected("vault_recovery_changed") { storage().recover("x".repeat(43)) }
        rejected("vault_invalid_input") { storage().recover("bad") }
        time += 300001
        rejected("vault_recovery_changed") { storage().recover(old.token) }
        val replacement = storage().prepareRecovery()!!
        assertNotEquals(old.token, replacement.token)
        rejected("vault_recovery_changed") { storage().recover(old.token) }
        assertEquals(2, records().size)
        assertFalse(storage().recover(replacement.token))
    }

    @Test
    fun clockRollbackAndRestoredAuthorityDoNotAuthorizeRecovery() {
        write()
        val original = key
        key = null
        val ticket = storage().prepareRecovery()!!
        time--
        rejected("vault_recovery_changed") { storage().recover(ticket.token) }
        time++
        key = original
        rejected("vault_recovery_changed") { storage().recover(ticket.token) }
        assertEquals("private-refresh-token", read())
        write(text = "new-session")
        key = null
        rejected("vault_recovery_changed") { storage().recover(ticket.token) }
        assertEquals(1, records().size)
    }

    @Test
    fun lockedOrUncertainConfirmationRetainsPreparedRecords() {
        val ticket = lost()
        locked = true
        rejected("vault_locked") { storage().recover(ticket.token) }
        locked = false
        uncertain = true
        rejected("vault_unavailable") { storage().recover(ticket.token) }
        assertEquals(2, records().size)
        uncertain = false
        assertFalse(storage().prepareRecovery()!!.inProgress)
    }

    @Test
    fun interruptedRecoveryIsFencedAndResumableAtEveryDurableBoundary() {
        for (point in listOf("authorized", "deleted-record", "records-cleared", "key-ready")) {
            val ticket = lost()
            checkpoint = { if (it == point) throw java.io.IOException("injected interruption") }
            rejected("vault_storage_failed") { storage().recover(ticket.token) }
            rejected("vault_recovery_pending") { read() }
            rejected("vault_recovery_pending") { write() }
            assertEquals(VaultRecoveryRequest(ticket.token, true), storage().prepareRecovery())
            // Recovery already authorized can continue after the prepared ticket expires.
            time += 600000
            checkpoint = {}
            assertFalse(storage().recover(ticket.token))
            assertTrue(storage().recover(ticket.token))
            assertNull(read(a))
            assertNull(read(b))
        }
    }

    @Test
    fun lostCompletionResponseIsIdempotentAndNeverClearsNewSessions() {
        val ticket = lost()
        checkpoint = { if (it == "complete") throw java.io.IOException("lost reply") }
        rejected("vault_storage_failed") { storage().recover(ticket.token) }
        checkpoint = {}
        write(text = "new-session")
        assertTrue(storage().recover(ticket.token))
        assertEquals("new-session", read())
        key = null
        val next = storage().prepareRecovery()!!
        rejected("vault_recovery_changed") { storage().recover(ticket.token) }
        assertNotEquals(next.token, ticket.token)
    }

    @Test
    fun failedAuthorizationSyncDoesNotDeleteCiphertext() {
        val ticket = lost()
        failSync = true
        rejected("vault_storage_failed") { storage().recover(ticket.token) }
        assertEquals(2, records().size)
        assertEquals(0, recoveries)
        // The retry sees authorized in memory even though its directory fsync
        // failed. It must establish durability before starting deletion.
        rejected("vault_storage_failed") { storage().recover(ticket.token) }
        assertEquals(2, records().size)
        failSync = false
        assertTrue(storage().prepareRecovery()!!.inProgress)
        assertFalse(storage().recover(ticket.token))
    }

    @Test
    fun rejectsCorruptOrUnrecognizedFilesWithoutDeletingOtherRecords() {
        val ticket = lost()
        File(directory, "unexpected").writeText("keep")
        rejected("vault_corrupt") { storage().recover(ticket.token) }
        assertEquals(2, records().size)
        File(directory, "unexpected").delete()
        val outside = File(root, "outside").apply { writeText("keep") }
        Files.createSymbolicLink(
            File(directory, "c".repeat(64) + ".vault").toPath(),
            outside.toPath(),
        )
        rejected("vault_corrupt") { storage().recover(ticket.token) }
        assertEquals("keep", outside.readText())
        assertEquals(3, records().size)
    }

    @Test
    fun malformedMarkerFailsClosedBeforeNormalStorageOrRecovery() {
        val ticket = lost()
        val marker = File(directory, ".recovery")
        val valid = marker.readBytes()
        val samples =
            listOf(
                byteArrayOf(0xc3.toByte(), 0x28),
                "[".repeat(500).toByteArray(),
                "x".repeat(1025).toByteArray(),
                valid
                    .toString(Charsets.UTF_8)
                    .replace("\"version\":1", "\"version\":1,\"version\":1")
                    .toByteArray(),
                valid.toString(Charsets.UTF_8).replace("prepared", "unknown").toByteArray(),
            )
        for (sample in samples) {
            marker.writeBytes(sample)
            rejected("vault_corrupt") { read() }
            rejected("vault_corrupt") { storage().prepareRecovery() }
            rejected("vault_corrupt") { storage().recover(ticket.token) }
            assertEquals(2, records().size)
        }
    }

    @Test
    fun recoveryInvalidatesPreviouslyHeldLeaseAndNeverReusesGenerations() {
        val vault = SessionVault(storage())
        val old = vault.acquire("issuer", "slot", "when-unlocked", 30000.0, false)
        key = null
        val ticket = storage().prepareRecovery()!!
        storage().recover(ticket.token)
        val fresh = vault.acquire("issuer", "slot", "when-unlocked", 30000.0, false)
        assertNotEquals(old.leaseId, fresh.leaseId)
        assertEquals(VaultRecoveryMarker.GENERATIONS_PER_EPOCH, fresh.generation)
        assertTrue(fresh.generation > old.generation)
        rejected("vault_lost_lease") {
            vault.commit(
                "issuer",
                "slot",
                old.leaseId,
                old.generation.toDouble(),
                null,
                "{\"refreshToken\":\"old\"}",
                null,
                false,
            )
        }
        vault.commit(
            "issuer",
            "slot",
            fresh.leaseId,
            fresh.generation.toDouble(),
            null,
            "{\"refreshToken\":\"new\"}",
            null,
            false,
        )
    }

    @Test
    fun invalidatedAuthorityWithoutRecordsStillHasAnExplicitRecoveryPath() {
        key = newKey()
        invalidatedKey = true
        val ticket = storage().prepareRecovery()!!
        assertTrue(records().isEmpty())
        val original = key
        assertSame(original, key)
        assertFalse(storage().recover(ticket.token))
        assertNotSame(original, key)
        assertFalse(invalidatedKey)
        assertEquals(1, recoveries)
        assertNull(storage().prepareRecovery())
    }

    @Test
    fun delayedCompensationCannotEraseNewSessionsAfterRecovery() {
        fun login(vault: SessionVault): Long {
            val held = vault.acquire("issuer", "slot", "when-unlocked", 30000.0, false)
            return vault.commit(
                "issuer",
                "slot",
                held.leaseId,
                held.generation.toDouble(),
                null,
                "{\"refreshToken\":\"session\"}",
                null,
                false,
            )
        }
        val vault = SessionVault(storage())
        val oldGeneration = login(vault)
        key = null
        storage().recover(storage().prepareRecovery()!!.token)
        val newGeneration = login(SessionVault(storage()))
        assertEquals(oldGeneration + VaultRecoveryMarker.GENERATIONS_PER_EPOCH, newGeneration)
        assertFalse(vault.discard("issuer", "slot", oldGeneration.toDouble()))
        val held = SessionVault(storage()).acquire("issuer", "slot", "when-unlocked", 30000.0, true)
        assertEquals("{\"refreshToken\":\"session\"}", held.sessionJSON)
    }

    @Test
    fun cancellingPreparedRecoveryPreservesThePreviousRecoveryEpoch() {
        val initial = lost()
        storage().recover(initial.token)
        write()
        val restoredKey = key
        key = null
        val cancelled = storage().prepareRecovery()!!
        key = restoredKey
        write()
        rejected("vault_recovery_changed") { storage().recover(cancelled.token) }
        val vault = SessionVault(storage())
        val first = vault.acquire("issuer", "slot", "when-unlocked", 30000.0, false)
        assertEquals(VaultRecoveryMarker.GENERATIONS_PER_EPOCH, first.generation)
        key = null
        val next = storage().prepareRecovery()!!
        storage().recover(next.token)
        val second = vault.acquire("issuer", "slot", "when-unlocked", 30000.0, false)
        assertEquals(2 * VaultRecoveryMarker.GENERATIONS_PER_EPOCH, second.generation)
    }

    @Test
    fun accountRevisionCannotOverflowIntoANewRecoveryEpoch() {
        val account = VaultCodec.account("issuer", "slot")
        val ceiling = VaultRecoveryMarker.GENERATIONS_PER_EPOCH - 1
        storage().transaction(account) {
            it.write(VaultCodec.encode(VaultRecord(account, generation = ceiling)))
        }
        val vault = SessionVault(storage())
        val held = vault.acquire("issuer", "slot", "when-unlocked", 30000.0, false)
        rejected("vault_corrupt") {
            vault.commit(
                "issuer",
                "slot",
                held.leaseId,
                held.generation.toDouble(),
                null,
                null,
                null,
                false,
            )
        }
        val actual = storage().transaction(account) { VaultCodec.decode(it.read()!!, account) }
        assertEquals(ceiling, actual.generation)
    }

    @Test
    fun recoveryEpochExhaustionNeverDeletesData() {
        val ticket = lost()
        val file = File(directory, ".recovery")
        val marker = VaultRecoveryMarker.decode(file.readBytes())
        file.writeBytes(marker.copy(epoch = VaultRecoveryMarker.MAX_EPOCH).encode())
        rejected("vault_storage_failed") { storage().recover(ticket.token) }
        assertEquals(2, records().size)
        assertEquals(0, recoveries)
    }

    @Test
    fun missingEpochAuthorityNeverRestartsGenerationsOrAuthorizesRecovery() {
        val ticket = lost()
        storage().recover(ticket.token)
        write()
        File(directory, ".recovery").delete()
        key = null
        rejected("vault_corrupt") { read() }
        rejected("vault_corrupt") { write() }
        rejected("vault_corrupt") { storage().prepareRecovery() }
        assertEquals(1, records().size)
    }
}
