package com.deviceattestation

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.UserManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

internal object AndroidVaultStorage {
    fun create(context: Context): EncryptedVaultStorage {
        val app = context.applicationContext
        fun unlocked() {
            requireNative(!app.isDeviceProtectedStorage, "vault_unavailable")
            requireNative(
                app.getSystemService(UserManager::class.java)?.isUserUnlocked == true &&
                    app.getSystemService(KeyguardManager::class.java)?.isDeviceLocked == false,
                "vault_locked",
            )
        }
        val alias = "DeviceAttestation.FirstParty.Vault.AES.v1"
        val keys = VaultEncryptionKey { allowCreation ->
            unlocked()
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!store.containsAlias(alias)) {
                requireNative(allowCreation, "vault_key_lost")
                val spec =
                    KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                        )
                        .setKeySize(256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true)
                        .setUnlockedDeviceRequired(true)
                        .setUserAuthenticationRequired(false)
                        .build()
                KeyGenerator.getInstance("AES", "AndroidKeyStore")
                    .apply { init(spec) }
                    .generateKey()
            }
            val key =
                store.getKey(alias, null) as? SecretKey ?: throw NativeFailure("vault_unavailable")
            val info =
                SecretKeyFactory.getInstance("AES", "AndroidKeyStore")
                    .getKeySpec(key, KeyInfo::class.java) as KeyInfo
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
                    key.algorithm == "AES" &&
                    info.keySize == 256 &&
                    info.origin == KeyProperties.ORIGIN_GENERATED &&
                    info.purposes ==
                        (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) &&
                    info.blockModes.toSet() == setOf(KeyProperties.BLOCK_MODE_GCM) &&
                    info.encryptionPaddings.toSet() ==
                        setOf(KeyProperties.ENCRYPTION_PADDING_NONE) &&
                    !info.isUserAuthenticationRequired,
                "vault_unavailable",
            )
            key
        }
        val recovery =
            object : VaultRecoveryKeys {
                override fun loss(): VaultKeyLoss? {
                    unlocked()
                    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    if (!store.containsAlias(alias)) return VaultKeyLoss.MISSING
                    return try {
                        val key = keys.get(false)
                        Cipher.getInstance("AES/GCM/NoPadding").apply {
                            init(Cipher.ENCRYPT_MODE, key)
                            doFinal(byteArrayOf())
                        }
                        null
                    } catch (_: KeyPermanentlyInvalidatedException) {
                        VaultKeyLoss.INVALIDATED
                    }
                }

                override fun recover() {
                    unlocked()
                    // Only invoked after durable authorization and ciphertext deletion.
                    // A healthy key can belong to an interrupted recovery: reuse it.
                    if (loss() != null) {
                        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                        if (store.containsAlias(alias)) store.deleteEntry(alias)
                        keys.get(true)
                    }
                    requireNative(loss() == null, "vault_key_lost")
                }
            }
        return EncryptedVaultStorage(
            File(app.noBackupFilesDir, "device-attestation-vault-v1"),
            keys,
            ::unlocked,
            syncDirectory = { directory ->
                val fd =
                    Os.open(
                        directory.absolutePath,
                        OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW,
                        0,
                    )
                try {
                    requireNative(OsConstants.S_ISDIR(Os.fstat(fd).st_mode), "vault_storage_failed")
                    Os.fsync(fd)
                } finally {
                    Os.close(fd)
                }
            },
            recoveryKeys = recovery,
            failure = { error ->
                NativeFailure(
                    if (error is KeyPermanentlyInvalidatedException) "vault_key_lost"
                    else "vault_storage_failed"
                )
            },
            restrict = { file, directory ->
                Os.chmod(file.absolutePath, if (directory) 448 else 384)
            },
        )
    }
}
