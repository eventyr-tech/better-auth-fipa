package com.deviceattestation

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributes
import java.util.concurrent.TimeUnit
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal fun interface VaultEncryptionKey {
    fun get(allowCreation: Boolean): SecretKey
}

internal object VaultEnvelope {
    const val MAX_BYTES = VaultCodec.MAX_RECORD_BYTES + 29

    private fun aad(account: String) =
        "device-attestation-vault/android/aes-gcm/v1:$account".toByteArray(Charsets.UTF_8)

    fun encrypt(account: String, plaintext: ByteArray, key: SecretKey): ByteArray {
        requireNative(plaintext.size <= VaultCodec.MAX_RECORD_BYTES, "vault_invalid_input")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        // AndroidKeyStore chooses a fresh randomized IV. Never reuse a caller IV.
        cipher.init(Cipher.ENCRYPT_MODE, key)
        requireNative(cipher.iv.size == 12, "vault_storage_failed")
        cipher.updateAAD(aad(account))
        return byteArrayOf(1) + cipher.iv + cipher.doFinal(plaintext)
    }

    fun decrypt(account: String, envelope: ByteArray, key: SecretKey): ByteArray {
        requireNative(envelope.size in 29..MAX_BYTES && envelope[0] == 1.toByte(), "vault_corrupt")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.copyOfRange(1, 13)))
        cipher.updateAAD(aad(account))
        return try {
            cipher.doFinal(envelope, 13, envelope.size - 13)
        } catch (_: AEADBadTagException) {
            throw NativeFailure("vault_corrupt")
        }
    }
}

/**
 * Real encrypted files and atomic replacement. Android supplies Keystore and lock checks; JVM tests
 * supply ephemeral test keys, never a production fallback.
 */
internal class EncryptedVaultStorage(
    private val directory: File,
    private val keys: VaultEncryptionKey,
    private val checkAccess: () -> Unit,
    private val syncDirectory: (File) -> Unit,
    private val restrict: (File, Boolean) -> Unit,
    private val beforeReplace: () -> Unit = {},
    private val recoveryKeys: VaultRecoveryKeys? = null,
    private val now: () -> Long = System::currentTimeMillis,
    private val recoveryCheckpoint: (String) -> Unit = {},
    private val failure: (Exception) -> NativeFailure = { NativeFailure("vault_storage_failed") },
) : SessionVaultStorage {
    companion object {
        private val processLock = Any()
    }

    override fun <T> transaction(account: String, operation: (VaultSlotStorage) -> T): T =
        exclusive {
            requireNative(account.matches(Regex("[0-9a-f]{64}")), "vault_invalid_input")
            val marker = recoveryMarker()
            // Every ciphertext write has a durable epoch marker, even before
            // the first recovery. Missing epoch authority is corruption, never
            // permission to restart generations and accept stale compensation.
            requireNative(marker != null || dataFiles().isEmpty(), "vault_corrupt")
            requireNative(marker?.phase != "authorized", "vault_recovery_pending")
            operation(
                object : VaultSlotStorage {
                    override val generationFloor =
                        (marker?.epoch ?: 0) * VaultRecoveryMarker.GENERATIONS_PER_EPOCH
                    override val generationCeiling =
                        generationFloor + VaultRecoveryMarker.GENERATIONS_PER_EPOCH - 1

                    override fun read(): ByteArray? {
                        checkAccess()
                        val file = File(directory, "$account.vault")
                        val attrs =
                            try {
                                Files.readAttributes(
                                    file.toPath(),
                                    BasicFileAttributes::class.java,
                                    LinkOption.NOFOLLOW_LINKS,
                                )
                            } catch (_: NoSuchFileException) {
                                return null
                            }
                        requireNative(
                            attrs.isRegularFile &&
                                attrs.size() in 29..VaultEnvelope.MAX_BYTES.toLong(),
                            "vault_corrupt",
                        )
                        val encrypted =
                            file.inputStream().use { input ->
                                val bytes = ByteArrayOutputStream()
                                val buffer = ByteArray(16384)
                                while (true) {
                                    val read = input.read(buffer)
                                    if (read == -1) break
                                    requireNative(
                                        bytes.size() + read <= VaultEnvelope.MAX_BYTES,
                                        "vault_corrupt",
                                    )
                                    bytes.write(buffer, 0, read)
                                }
                                bytes.toByteArray()
                            }
                        return VaultEnvelope.decrypt(account, encrypted, keys.get(false))
                    }

                    override fun write(bytes: ByteArray) {
                        checkAccess()
                        // Marker/lock metadata is not ciphertext. Existing records
                        // always prevent an implicit replacement encryption key.
                        val createKey = dataFiles().isEmpty()
                        val encrypted = VaultEnvelope.encrypt(account, bytes, keys.get(createKey))
                        if (marker == null) {
                            requireNative(now() > 0, "vault_unavailable")
                            saveRecovery(
                                VaultRecoveryMarker(
                                    FirstPartyCrypto.randomToken(),
                                    "cancelled",
                                    now(),
                                )
                            )
                        }
                        // A successful encryption proves authority is usable again.
                        // Revoke any prepared recovery ticket before a new write.
                        if (marker?.phase == "prepared") {
                            saveRecovery(marker.copy(phase = "cancelled"))
                        }
                        val temporary = File.createTempFile(".pending-", ".vault", directory)
                        try {
                            restrict(temporary, false)
                            FileOutputStream(temporary).use { stream ->
                                stream.write(encrypted)
                                stream.fd.sync()
                            }
                            beforeReplace()
                            checkAccess()
                            Files.move(
                                temporary.toPath(),
                                File(directory, "$account.vault").toPath(),
                                StandardCopyOption.ATOMIC_MOVE,
                                StandardCopyOption.REPLACE_EXISTING,
                            )
                            syncDirectory(directory)
                        } finally {
                            temporary.delete()
                        }
                    }
                }
            )
        }

    private fun <T> exclusive(operation: () -> T): T =
        synchronized(processLock) {
            try {
                checkAccess()
                requireNative(!Thread.currentThread().isInterrupted, "vault_unavailable")
                if (!directory.isDirectory) {
                    requireNative(
                        directory.mkdirs() || directory.isDirectory,
                        "vault_storage_failed",
                    )
                    restrict(directory, true)
                    syncDirectory(directory.parentFile!!)
                }
                val lockFile = File(directory, ".lock")
                RandomAccessFile(lockFile, "rw").use { lockHandle ->
                    restrict(lockFile, false)
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                    var lock: java.nio.channels.FileLock? = null
                    while (lock == null) {
                        lock =
                            try {
                                lockHandle.channel.tryLock()
                            } catch (_: OverlappingFileLockException) {
                                null
                            }
                        if (lock == null) {
                            requireNative(System.nanoTime() - deadline < 0, "vault_busy")
                            Thread.sleep(25)
                        }
                    }
                    try {
                        checkAccess()
                        operation()
                    } finally {
                        lock.release()
                    }
                }
            } catch (error: NativeFailure) {
                throw error
            } catch (error: Exception) {
                throw failure(error)
            }
        }

    private fun dataFiles(): List<File> {
        val files = directory.listFiles() ?: throw NativeFailure("vault_storage_failed")
        requireNative(files.size <= 4096, "vault_storage_failed")
        return files.filter { file ->
            val metadata =
                file.name in setOf(".lock", ".recovery") ||
                    (file.name.startsWith(".metadata-") && file.name.endsWith(".tmp"))
            if (!metadata) {
                requireNative(
                    file.name.matches(Regex("[0-9a-f]{64}\\.vault")) ||
                        (file.name.startsWith(".pending-") && file.name.endsWith(".vault")),
                    "vault_corrupt",
                )
                requireNative(
                    Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS),
                    "vault_corrupt",
                )
            }
            !metadata
        }
    }

    private fun recoveryMarker(): VaultRecoveryMarker? {
        val file = File(directory, ".recovery")
        val attrs =
            try {
                Files.readAttributes(
                    file.toPath(),
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
            } catch (_: NoSuchFileException) {
                return null
            }
        requireNative(attrs.isRegularFile && attrs.size() in 1..1024, "vault_corrupt")
        val bytes =
            file.inputStream().use { input ->
                val buffer = ByteArrayOutputStream()
                val chunk = ByteArray(1025)
                while (true) {
                    val count = input.read(chunk)
                    if (count == -1) break
                    requireNative(buffer.size() + count <= 1024, "vault_corrupt")
                    buffer.write(chunk, 0, count)
                }
                buffer.toByteArray()
            }
        return VaultRecoveryMarker.decode(bytes)
    }

    private fun saveRecovery(marker: VaultRecoveryMarker) {
        val temporary = File.createTempFile(".metadata-", ".tmp", directory)
        try {
            restrict(temporary, false)
            FileOutputStream(temporary).use { stream ->
                stream.write(marker.encode())
                stream.fd.sync()
            }
            checkAccess()
            Files.move(
                temporary.toPath(),
                File(directory, ".recovery").toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            syncDirectory(directory)
        } finally {
            temporary.delete()
        }
    }

    /**
     * Preparing never discards records or replaces keys. Authorization is a separate bridge call
     * with the exact returned, short-lived ticket.
     */
    fun prepareRecovery(): VaultRecoveryRequest? = exclusive {
        val authority = recoveryKeys ?: throw NativeFailure("vault_unavailable")
        val marker = recoveryMarker()
        if (marker?.phase == "authorized") return@exclusive VaultRecoveryRequest(marker.token, true)
        val files = dataFiles()
        requireNative(marker != null || files.isEmpty(), "vault_corrupt")
        val loss = authority.loss()
        if (loss == null || (files.isEmpty() && loss == VaultKeyLoss.MISSING)) {
            if (marker?.phase == "prepared") {
                saveRecovery(marker.copy(phase = "cancelled"))
            }
            return@exclusive null
        }
        val current = now()
        if (
            marker?.phase == "prepared" &&
                current >= marker.preparedAt &&
                current - marker.preparedAt <= 300000
        )
            return@exclusive VaultRecoveryRequest(marker.token, false)
        requireNative(current > 0, "vault_unavailable")
        val prepared =
            VaultRecoveryMarker(
                FirstPartyCrypto.randomToken(),
                "prepared",
                current,
                marker?.epoch ?: 0,
            )
        saveRecovery(prepared)
        VaultRecoveryRequest(prepared.token, false)
    }

    /**
     * Global to this native vault, including every configured account catalog. Stable .lock is
     * never renamed. The authorized journal blocks normal work until deletion/rekey is durable, and
     * makes interruption/retry explicit.
     */
    fun recover(token: String): Boolean = exclusive {
        requireNative(token.matches(Regex("[A-Za-z0-9_-]{43}")), "vault_invalid_input")
        val authority = recoveryKeys ?: throw NativeFailure("vault_unavailable")
        var marker = recoveryMarker() ?: throw NativeFailure("vault_recovery_changed")
        requireNative(marker.token == token, "vault_recovery_changed")
        if (marker.phase == "complete") {
            syncDirectory(directory)
            return@exclusive true
        }
        requireNative(marker.phase != "cancelled", "vault_recovery_changed")
        if (marker.phase == "prepared") {
            val current = now()
            requireNative(
                current >= marker.preparedAt && current - marker.preparedAt <= 300000,
                "vault_recovery_changed",
            )
            val files = dataFiles()
            val loss = authority.loss()
            requireNative(
                loss != null && (files.isNotEmpty() || loss == VaultKeyLoss.INVALIDATED),
                "vault_recovery_changed",
            )
            requireNative(marker.epoch < VaultRecoveryMarker.MAX_EPOCH, "vault_storage_failed")
            marker = marker.copy(phase = "authorized", epoch = marker.epoch + 1)
            saveRecovery(marker)
        }
        // A prior attempt may have failed directory fsync after marker rename.
        // Reestablish journal durability before deleting any ciphertext.
        syncDirectory(directory)
        recoveryCheckpoint("authorized")
        // Validate the whole directory before deleting any data; never traverse
        // symlinks or touch files outside the library's private directory.
        val files = dataFiles()
        for (file in files) {
            checkAccess()
            Files.delete(file.toPath())
            recoveryCheckpoint("deleted-record")
        }
        syncDirectory(directory)
        recoveryCheckpoint("records-cleared")
        checkAccess()
        authority.recover()
        recoveryCheckpoint("key-ready")
        saveRecovery(marker.copy(phase = "complete"))
        recoveryCheckpoint("complete")
        false
    }
}
