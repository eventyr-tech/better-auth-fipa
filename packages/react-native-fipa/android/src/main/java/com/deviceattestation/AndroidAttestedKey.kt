package com.deviceattestation

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.os.UserManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Direct, nonexportable AndroidKeyStore key. The server, not this local check, validates Google's
 * chain, security properties, challenge and actual proof key.
 */
internal class AndroidAttestedKey(private val context: Context) {
    companion object {
        private val processLock = Any()
    }

    private fun name(alias: String): String {
        requireNative(alias.isNotEmpty() && alias.toByteArray().size <= 256)
        return "DeviceAttestation.FirstParty.Android.v1." + FirstPartyCrypto.sha256Utf8(alias)
    }

    private fun unlocked() {
        requireNative(!Thread.currentThread().isInterrupted, "key_cancelled")
        requireNative(!context.isDeviceProtectedStorage, "key_unavailable")
        requireNative(
            context.getSystemService(UserManager::class.java)?.isUserUnlocked == true &&
                context.getSystemService(KeyguardManager::class.java)?.isDeviceLocked == false,
            "key_locked",
        )
    }

    private fun <T> locked(block: () -> T): T =
        synchronized(processLock) {
            unlocked()
            // Shared by all module/runtime instances and app processes. noBackup is
            // credential-encrypted app storage; no aliases or private keys go in it.
            val file = File(context.noBackupFilesDir, "device-attestation-keys.lock")
            RandomAccessFile(file, "rw").use { handle ->
                val deadline = SystemClock.elapsedRealtime() + 10000
                var lock: java.nio.channels.FileLock? = null
                while (lock == null) {
                    lock =
                        try {
                            handle.channel.tryLock()
                        } catch (_: OverlappingFileLockException) {
                            null
                        }
                    if (lock == null) {
                        requireNative(SystemClock.elapsedRealtime() < deadline, "key_busy")
                        Thread.sleep(25)
                    }
                }
                try {
                    unlocked()
                    block()
                } finally {
                    lock.release()
                }
            }
        }

    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun entry(store: KeyStore, alias: String): KeyStore.PrivateKeyEntry? {
        if (!store.containsAlias(alias)) return null
        val entry =
            store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
                ?: throw NativeFailure("key_unavailable")
        val info =
            KeyFactory.getInstance("EC", "AndroidKeyStore")
                .getKeySpec(entry.privateKey, KeyInfo::class.java)
        @Suppress("DEPRECATION")
        val hardware =
            if (Build.VERSION.SDK_INT >= 31)
                info.securityLevel in
                    listOf(
                        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                        KeyProperties.SECURITY_LEVEL_STRONGBOX,
                    )
            else info.isInsideSecureHardware
        requireNative(
            hardware &&
                info.keySize == 256 &&
                info.origin == KeyProperties.ORIGIN_GENERATED &&
                info.purposes == KeyProperties.PURPOSE_SIGN &&
                info.digests.toSet() == setOf(KeyProperties.DIGEST_SHA256) &&
                !info.isUserAuthenticationRequired,
            "key_unavailable",
        )
        publicKey(entry)
        return entry
    }

    private fun publicKey(entry: KeyStore.PrivateKeyEntry): ECPublicKey {
        val public =
            entry.certificate.publicKey as? ECPublicKey ?: throw NativeFailure("key_unavailable")
        FirstPartyCrypto.publicJwk(public) // Exact P-256 parameters, not only bit length.
        return public
    }

    private fun matched(
        store: KeyStore,
        alias: String,
        expected: String,
    ): KeyStore.PrivateKeyEntry {
        FirstPartyCrypto.decodeDigest(expected)
        val entry = entry(store, alias) ?: throw NativeFailure("key_missing")
        requireNative(FirstPartyCrypto.thumbprint(publicKey(entry)) == expected, "key_mismatch")
        return entry
    }

    fun inspect(alias: String): String? = locked {
        entry(store(), name(alias))?.let { FirstPartyCrypto.thumbprint(publicKey(it)) }
    }

    fun create(alias: String, challenge: String, level: String): String = locked {
        val keyName = name(alias)
        val nonce = FirstPartyCrypto.decodeDigest(challenge)
        requireNative(level in listOf("tee", "strongbox"))
        val store = store()
        requireNative(!store.containsAlias(keyName), "key_exists")
        val spec =
            KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(nonce)
                .setUserAuthenticationRequired(false)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(level == "strongbox")
                .build()
        // No retry without StrongBox, no software provider, no generate-on-read.
        KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
            .apply { initialize(spec) }
            .generateKeyPair()
        val created = entry(store, keyName) ?: throw NativeFailure("key_failed")
        val info =
            KeyFactory.getInstance("EC", "AndroidKeyStore")
                .getKeySpec(created.privateKey, KeyInfo::class.java)
        if (level == "strongbox" && Build.VERSION.SDK_INT >= 31)
            requireNative(
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX,
                "key_unavailable",
            )
        FirstPartyCrypto.thumbprint(publicKey(created))
    }

    fun certificateChain(alias: String, expected: String): List<String> = locked {
        val store = store()
        val keyName = name(alias)
        val entry = matched(store, keyName, expected)
        val chain = store.getCertificateChain(keyName) ?: throw NativeFailure("key_unavailable")
        requireNative(
            chain.size in 4..5 &&
                chain[0].publicKey.encoded.contentEquals(entry.certificate.publicKey.encoded),
            "key_unavailable",
        )
        chain.map { certificate ->
            val bytes = certificate.encoded
            requireNative(bytes.size in 1..16384, "key_unavailable")
            Base64.getEncoder().encodeToString(bytes)
        }
    }

    fun remove(alias: String, expected: String) = locked {
        FirstPartyCrypto.decodeDigest(expected)
        val store = store()
        val keyName = name(alias)
        if (store.containsAlias(keyName)) {
            matched(store, keyName, expected)
            store.deleteEntry(keyName)
        }
    }

    fun sign(
        alias: String,
        expected: String,
        url: String,
        method: String,
        accessToken: String?,
        nonce: String?,
    ): String = locked {
        val entry = matched(store(), name(alias), expected)
        val input =
            FirstPartyCrypto.proofInput(publicKey(entry), expected, url, method, accessToken, nonce)
        val signer =
            Signature.getInstance("SHA256withECDSA").apply {
                initSign(entry.privateKey)
                update(input.toByteArray(Charsets.UTF_8))
            }
        input + "." + FirstPartyCrypto.encode(FirstPartyCrypto.joseSignature(signer.sign()))
    }
}
