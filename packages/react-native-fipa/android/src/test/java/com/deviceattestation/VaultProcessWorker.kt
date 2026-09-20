package com.deviceattestation

import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import javax.crypto.spec.SecretKeySpec

/**
 * Test-only software key and separate JVM process; never packaged or used by AndroidVaultStorage.
 * Exercises the actual on-disk interprocess lock.
 */
object VaultProcessWorker {
    @JvmStatic
    fun main(args: Array<String>) {
        val directory = File(args[0])
        val ready = File(args[1])
        val start = File(args[2])
        val storage =
            EncryptedVaultStorage(
                directory,
                { SecretKeySpec(ByteArray(32) { 7 }, "AES") },
                {},
                { file ->
                    FileChannel.open(file.toPath(), StandardOpenOption.READ).use { it.force(true) }
                },
                { _, _ -> },
            )
        ready.writeText("ready")
        val deadline = System.nanoTime() + 10_000_000_000
        while (!start.exists()) {
            check(System.nanoTime() < deadline) { "Test synchronization timed out" }
            Thread.sleep(5)
        }
        try {
            SessionVault(storage).acquire("issuer|client", "slot", "when-unlocked", 30000.0, false)
            println("acquired")
        } catch (error: NativeFailure) {
            println(error.code)
        }
    }
}
