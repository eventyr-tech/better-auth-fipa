package io.eventyr.attestationlab

import android.app.KeyguardManager
import com.facebook.react.ReactPackage
import com.facebook.react.bridge.*
import com.facebook.react.uimanager.ViewManager
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import org.json.JSONObject

// App-only fault injector. Included solely by the opt-in lab config plugin.
class AttestationLabPackage : ReactPackage {
    override fun createNativeModules(context: ReactApplicationContext): List<NativeModule> =
        listOf(AttestationLabDiagnostics(context))
    override fun createViewManagers(context: ReactApplicationContext): List<ViewManager<*, *>> = emptyList()
}
class AttestationLabDiagnostics(private val app: ReactApplicationContext) : ReactContextBaseJavaModule(app) {
    override fun getName() = "AttestationLabDiagnostics"
    private val alias = "DeviceAttestation.FirstParty.Vault.AES.v1"
    private fun digest(bytes: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun snapshot(): JSONObject {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val certificates = JSONObject()
        store.aliases().toList().sorted().forEach { name ->
            store.getCertificate(name)?.let { certificates.put(digest(name.toByteArray()), digest(it.publicKey.encoded)) }
        }
        val files = JSONObject()
        File(app.noBackupFilesDir, "device-attestation-vault-v1").listFiles()
            ?.filter { it.name.endsWith(".vault") }?.sortedBy { it.name }
            ?.forEach { files.put(it.name, digest(it.readBytes())) }
        return JSONObject().put("vaultKeyPresent", store.containsAlias(alias))
            .put("signingPublicKeys", certificates).put("ciphertextHashes", files)
    }
    private fun baseline() = File(app.filesDir, "attestation-lab-vault-baseline.json")
    @ReactMethod fun inspect(promise: Promise) {
        try {
            val result = JSONObject().put("current", snapshot())
            if (baseline().exists()) result.put("beforeKeyLoss", JSONObject(baseline().readText()))
            promise.resolve(result.toString())
        } catch (e: Exception) { promise.reject("lab_inspection_failed", e) }
    }
    @ReactMethod fun loseVaultKey(promise: Promise) {
        try {
            check(app.getSystemService(KeyguardManager::class.java)?.isDeviceLocked == false)
            val before = snapshot()
            check(before.getBoolean("vaultKeyPresent")) { "Vault key is already missing" }
            check(before.getJSONObject("ciphertextHashes").length() > 0) { "Save a session first" }
            baseline().writeText(before.toString())
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
            promise.resolve(JSONObject().put("beforeKeyLoss", before).put("current", snapshot()).toString())
        } catch (e: Exception) { promise.reject("lab_key_loss_failed", e) }
    }
}
