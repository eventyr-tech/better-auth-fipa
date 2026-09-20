package com.deviceattestation

import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class EncryptedVaultStorageTest {
    private val root = Files.createTempDirectory("android-encrypted-vault-test-").toFile()
    private val directory = File(root, "vault")
    private var key: SecretKey? = null
    private val creationRequests = mutableListOf<Boolean>()
    private var locked = false
    private var failReplace = false
    private var failSync = false

    private fun storage() =
        EncryptedVaultStorage(
            directory,
            { allowCreation ->
                creationRequests.add(allowCreation)
                if (key == null) {
                    requireNative(allowCreation, "vault_unavailable")
                    key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
                }
                key!!
            },
            { requireNative(!locked, "vault_locked") },
            { file ->
                if (failSync) throw java.io.IOException("test-only fsync failure")
                FileChannel.open(file.toPath(), StandardOpenOption.READ).use { it.force(true) }
            },
            { file, isDirectory ->
                Files.setPosixFilePermissions(
                    file.toPath(),
                    java.nio.file.attribute.PosixFilePermissions.fromString(
                        if (isDirectory) "rwx------" else "rw-------"
                    ),
                )
            },
            { if (failReplace) throw java.io.IOException("test-only replace failure") },
        )

    private fun vault() = SessionVault(storage())

    private fun acquire(instance: SessionVault = vault(), slot: String = "slot") =
        instance.acquire("issuer|client", slot, "when-unlocked", 30000.0, false)

    private fun commit(instance: SessionVault, held: VaultSnapshot) =
        instance.commit(
            "issuer|client",
            "slot",
            held.leaseId,
            held.generation.toDouble(),
            "{\"key\":\"private-alias\"}",
            "{\"refreshToken\":\"secret-token\"}",
            null,
            false,
        )

    private fun file(slot: String = "slot") =
        File(directory, VaultCodec.account("issuer|client", slot) + ".vault")

    private fun rejected(code: String, operation: () -> Unit) {
        try {
            operation()
            fail("Expected rejection")
        } catch (error: NativeFailure) {
            assertEquals(code, error.code)
        }
    }

    @After
    fun cleanup() {
        root.deleteRecursively()
    }

    @Test
    fun separatesRealProcessesWithTheOnDiskLock() {
        val classes =
            listOf(
                VaultProcessWorker::class.java,
                SessionVault::class.java,
                kotlinx.serialization.json.Json::class.java,
                kotlinx.serialization.SerializationException::class.java,
                kotlin.Unit::class.java,
            )
        val classPath =
            classes
                .map { File(it.protectionDomain.codeSource.location.toURI()).absolutePath }
                .distinct()
                .joinToString(File.pathSeparator)
        val start = File(root, "start")
        val ready = listOf(File(root, "ready-a"), File(root, "ready-b"))
        val processes =
            ready.map { marker ->
                ProcessBuilder(
                        File(System.getProperty("java.home"), "bin/java").absolutePath,
                        "-cp",
                        classPath,
                        VaultProcessWorker::class.java.name,
                        directory.absolutePath,
                        marker.absolutePath,
                        start.absolutePath,
                    )
                    .redirectErrorStream(true)
                    .start()
            }
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (!ready.all { it.exists() }) {
                assertTrue("Worker failed before synchronization", processes.all { it.isAlive })
                assertTrue("Workers did not become ready", System.nanoTime() < deadline)
                Thread.sleep(10)
            }
            start.writeText("start")
            val outcomes =
                processes.map { process ->
                    assertTrue(process.waitFor(10, TimeUnit.SECONDS))
                    val output = process.inputStream.bufferedReader().readText().trim()
                    assertEquals(output, 0, process.exitValue())
                    output
                }
            assertEquals(listOf("acquired", "vault_busy"), outcomes.sorted())
        } finally {
            processes.filter { it.isAlive }.forEach { it.destroyForcibly() }
        }
    }

    @Test
    fun storesOnlyAuthenticatedCiphertextAndRestoresAcrossInstances() {
        val instance = vault()
        commit(instance, acquire(instance))
        assertTrue(file().exists())
        val bytes = file().readBytes()
        assertEquals(1.toByte(), bytes[0])
        assertFalse(String(bytes).contains("secret-token"))
        assertFalse(String(bytes).contains("private-alias"))
        assertFalse(String(bytes).contains("issuer|client"))
        val restored = acquire()
        assertEquals("{\"refreshToken\":\"secret-token\"}", restored.sessionJSON)
        assertEquals("{\"key\":\"private-alias\"}", restored.identityJSON)
        assertEquals(listOf(true, false, false, false, false), creationRequests)
        assertTrue(directory.listFiles()!!.none { it.name.startsWith(".pending-") })
    }

    @Test
    fun randomizesIvEvenForIdenticalPlaintext() {
        val storage = storage()
        val account = VaultCodec.account("issuer|client", "slot")
        val data = VaultCodec.encode(VaultRecord(account))
        storage.transaction(account) { it.write(data) }
        val first = file().readBytes()
        storage.transaction(account) { it.write(data) }
        val second = file().readBytes()
        assertFalse(first.contentEquals(second))
        assertFalse(first.copyOfRange(1, 13).contentEquals(second.copyOfRange(1, 13)))
        assertArrayEquals(data, storage.transaction(account) { it.read() })
    }

    @Test
    fun rejectsTamperingTruncationAndRecordSubstitution() {
        acquire()
        acquire(slot = "other")
        val original = file().readBytes()
        for (bytes in
            listOf(
                original.clone().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
                original.copyOf(20),
                original.clone().also { it[0] = 2 },
                file("other").readBytes(),
            )) {
            file().writeBytes(bytes)
            rejected("vault_corrupt") { acquire() }
        }
        file().writeBytes(original)
        rejected("vault_busy") { acquire() }
    }

    @Test
    fun missingKeyNeverResetsExistingCiphertextOrCreatesNewSlotAuthority() {
        acquire()
        val bytes = file().readBytes()
        key = null
        rejected("vault_unavailable") { acquire() }
        rejected("vault_unavailable") { acquire(slot = "other") }
        assertNull(key)
        assertFalse(file("other").exists())
        assertArrayEquals(bytes, file().readBytes())
        assertFalse(creationRequests.last())
    }

    @Test
    fun failureBeforeAtomicReplacePreservesOldGenerationAndCleansTemporaryFile() {
        val instance = vault()
        val held = acquire(instance)
        val previous = file().readBytes()
        failReplace = true
        rejected("vault_storage_failed") { commit(instance, held) }
        assertArrayEquals(previous, file().readBytes())
        assertTrue(directory.listFiles()!!.none { it.name.startsWith(".pending-") })
        failReplace = false
        assertEquals(1L, commit(instance, held))
        assertNotNull(acquire().sessionJSON)
    }

    @Test
    fun lostWriteAcknowledgementCanOnlyBeCompensatedAtItsCurrentGeneration() {
        val instance = vault()
        val held = acquire(instance)
        failSync = true
        rejected("vault_storage_failed") { commit(instance, held) }
        failSync = false
        rejected("vault_lost_lease") { commit(instance, held) }
        assertTrue(instance.discard("issuer|client", "slot", 1.0))
        assertNull(acquire().sessionJSON)
    }

    @Test
    fun lockFailuresNeverReadAsAbsenceOrWriteThroughLock() {
        val instance = vault()
        val held = acquire(instance)
        val bytes = file().readBytes()
        locked = true
        rejected("vault_locked") { commit(instance, held) }
        rejected("vault_locked") { acquire(slot = "other") }
        assertArrayEquals(bytes, file().readBytes())
        assertFalse(file("other").exists())
        locked = false
        assertEquals(1L, commit(instance, held))
    }

    @Test
    fun distinctInstancesSerializeConcurrentAcquisition() {
        val pool = Executors.newFixedThreadPool(4)
        val start = CountDownLatch(1)
        try {
            val results =
                (1..8).map {
                    pool.submit(
                        Callable {
                            start.await()
                            try {
                                acquire().leaseId
                                "acquired"
                            } catch (error: NativeFailure) {
                                error.code
                            }
                        }
                    )
                }
            start.countDown()
            val outcomes = results.map { it.get(5, TimeUnit.SECONDS) }
            assertEquals(1, outcomes.count { it == "acquired" })
            assertEquals(7, outcomes.count { it == "vault_busy" })
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun refusesOversizedFilesSymlinksAndMalformedPlaintext() {
        val storage = storage()
        val account = VaultCodec.account("issuer|client", "slot")
        storage.transaction(account) { it.write("{}".toByteArray()) }
        rejected("vault_corrupt") { acquire() }
        file().writeBytes(ByteArray(VaultEnvelope.MAX_BYTES + 1))
        rejected("vault_corrupt") { acquire() }
        file().delete()
        Files.createSymbolicLink(file().toPath(), File(root, "missing").toPath())
        rejected("vault_corrupt") { acquire() }
        rejected("vault_invalid_input") { storage.transaction("../../other") { it.read() } }
    }

    @Test
    fun abandonedTemporaryCiphertextDoesNotPermitKeyReplacement() {
        directory.mkdirs()
        // The writer durably establishes epoch authority before creating even
        // a temporary ciphertext file. Missing epoch metadata is tested as
        // corruption separately from missing encryption authority.
        File(directory, ".recovery")
            .writeBytes(
                VaultRecoveryMarker(FirstPartyCrypto.randomToken(), "cancelled", 1).encode()
            )
        File(directory, ".pending-crashed.vault").writeBytes(byteArrayOf(1, 2, 3))
        rejected("vault_unavailable") { acquire() }
        assertNull(key)
        assertTrue(File(directory, ".pending-crashed.vault").exists())
    }
}
