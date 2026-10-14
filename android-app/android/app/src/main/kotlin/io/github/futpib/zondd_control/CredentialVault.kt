package io.github.futpib.zondd_control

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.ChecksSdkIntAtLeast
import androidx.annotation.RequiresApi
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class CredentialVault(private val activity: Activity) : MethodChannel.MethodCallHandler {
    private val preferences = activity.getSharedPreferences("credential-vault-v1", Activity.MODE_PRIVATE)
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val handler = Handler(Looper.getMainLooper())
    private var cancel: (() -> Unit)? = null
    private val prefix = "zond-credential-v1-"

    fun cancelPending() { cancel?.invoke() }

    private fun boot() = Settings.Global.getInt(activity.contentResolver, Settings.Global.BOOT_COUNT, -1)

    private fun expired(record: JSONObject): Boolean {
        val now = System.currentTimeMillis()
        val expires = record.getLong("expires")
        if (expires == 0L) return false
        if (now < record.getLong("created")) return true
        return expires != 0L && (now >= expires ||
            (record.getInt("boot") == boot() && SystemClock.elapsedRealtime() >= record.getLong("deadline")))
    }

    private fun remove(id: String) {
        check(preferences.edit().remove(id).commit())
        if (keys.containsAlias(prefix + id)) keys.deleteEntry(prefix + id)
    }

    private fun record(id: String): JSONObject? {
        val value = preferences.getString(id, null) ?: return null
        return try {
            JSONObject(value).also { if (expired(it)) { remove(id); return null } }
        } catch (_: Exception) { remove(id); null }
    }

    @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.R)
    private fun available(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
        activity.getSystemService(BiometricManager::class.java)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    @RequiresApi(Build.VERSION_CODES.R)
    private fun key(id: String): SecretKey {
        val alias = prefix + id
        if (keys.containsAlias(alias)) return keys.getKey(alias, null) as SecretKey
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .build())
        }.generateKey()
    }

    private fun aad(id: String, record: JSONObject) = listOf(
        id, record.getLong("created"), record.getLong("expires"),
        record.getInt("boot"), record.getLong("deadline"), record.getJSONObject("metadata").toString()
    ).joinToString("\n").toByteArray(Charsets.UTF_8)

    private fun authenticate(cipher: Cipher, result: MethodChannel.Result, saving: Boolean, work: () -> Any?) {
        if (!available()) {
            result.error("unavailable", "Set up strong biometrics on Android 11 or newer to save credentials.", null)
            return
        }
        if (cancel != null) {
            result.error("busy", "Another credential unlock is in progress.", null)
            return
        }
        val signal = CancellationSignal()
        var completed = false
        lateinit var timeout: Runnable
        fun finish(value: Any?, code: String? = null) {
            if (completed) return
            completed = true
            handler.removeCallbacks(timeout)
            cancel = null
            signal.cancel()
            if (code == null) result.success(value)
            else result.error(code, when (code) {
                "cancelled" -> "Biometric unlock cancelled."
                "expired" -> "Saved credentials expired. Enter them again."
                else -> "Saved credentials are unavailable. Remove them and enter them again."
            }, null)
        }
        timeout = Runnable { finish(null, "cancelled") }
        cancel = { finish(null, "cancelled") }
        handler.postDelayed(timeout, 60000)
        try {
            check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
            BiometricPrompt.Builder(activity)
                .setTitle(if (saving) "Save credentials" else "Unlock saved credentials")
                .setSubtitle("Use your fingerprint or strong face unlock")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setConfirmationRequired(true)
                .setNegativeButton("Cancel", activity.mainExecutor) { _, _ -> finish(null, "cancelled") }
                .build().authenticate(BiometricPrompt.CryptoObject(cipher), signal, activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(authentication: BiometricPrompt.AuthenticationResult) {
                            if (completed) return
                            try { finish(work()) }
                            catch (_: Expired) { finish(null, "expired") }
                            catch (_: Exception) { finish(null, "invalidated") }
                        }
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            finish(null, "cancelled")
                        }
                    })
        } catch (_: Exception) { finish(null, "invalidated") }
    }

    private class Expired : Exception()

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        try {
            if (call.method == "available") { result.success(available()); return }
            if (call.method == "list") {
                result.success(preferences.all.keys.toList().mapNotNull { id ->
                    record(id)?.let { value -> mapOf("id" to id, "created" to value.getLong("created"),
                        "expires" to value.getLong("expires"), "metadata" to value.getJSONObject("metadata").toString()) }
                })
                return
            }
            if (call.method == "deleteAll") {
                cancelPending()
                preferences.all.keys.toList().forEach { remove(it) }
                keys.aliases().toList().filter { it.startsWith(prefix) }.forEach { keys.deleteEntry(it) }
                result.success(null)
                return
            }
            val id = call.argument<String>("id") ?: error("missing id")
            require(Regex("^[a-f0-9]{64}$").matches(id))
            when (call.method) {
                "delete" -> { cancelPending(); remove(id); result.success(null) }
                "save" -> {
                    if (!available()) { result.error("unavailable", "Strong biometrics are required to save credentials.", null); return }
                    require(cancel == null)
                    val ttl = call.argument<Number>("seconds")?.toLong() ?: error("missing duration")
                    require(ttl in listOf(0L, 900L, 3600L, 28800L))
                    require(preferences.contains(id) || preferences.all.size < 64)
                    val values = call.argument<String>("values") ?: error("missing values")
                    require(values.toByteArray().size <= 131072)
                    val metadata = call.argument<String>("metadata") ?: error("missing metadata")
                    require(metadata.toByteArray().size <= 8192)
                    val created = System.currentTimeMillis()
                    val entry = JSONObject().put("created", created)
                        .put("expires", if (ttl == 0L) 0 else created + ttl * 1000)
                        .put("boot", boot()).put("deadline", SystemClock.elapsedRealtime() + ttl * 1000)
                        .put("metadata", JSONObject(metadata))
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                        init(Cipher.ENCRYPT_MODE, key(id))
                    }
                    authenticate(cipher, result, true) {
                        if (expired(entry)) throw Expired()
                        val clear = JSONObject().put("id", id).put("values", JSONObject(values)).toString().toByteArray()
                        try {
                            cipher.updateAAD(aad(id, entry))
                            entry.put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                            entry.put("ciphertext", Base64.encodeToString(cipher.doFinal(clear), Base64.NO_WRAP))
                            check(preferences.edit().putString(id, entry.toString()).commit())
                        } finally { clear.fill(0) }
                        null
                    }
                }
                "unlock" -> {
                    if (!available()) { result.error("unavailable", "Strong biometrics are required to unlock saved credentials.", null); return }
                    val entry = record(id)
                    if (entry == null) { result.error("expired", "Saved credentials expired or were removed.", null); return }
                    val stored = preferences.getString(id, null)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                        init(Cipher.DECRYPT_MODE, keys.getKey(prefix + id, null) as SecretKey,
                            GCMParameterSpec(128, Base64.decode(entry.getString("iv"), Base64.NO_WRAP)))
                    }
                    authenticate(cipher, result, false) {
                        if (expired(entry) || preferences.getString(id, null) != stored) throw Expired()
                        cipher.updateAAD(aad(id, entry))
                        val clear = cipher.doFinal(Base64.decode(entry.getString("ciphertext"), Base64.NO_WRAP))
                        try {
                            val payload = JSONObject(String(clear, Charsets.UTF_8))
                            check(payload.getString("id") == id)
                            payload.getJSONObject("values").toString()
                        } finally { clear.fill(0) }
                    }
                }
                else -> result.notImplemented()
            }
        } catch (_: Exception) {
            result.error("unavailable", "Saved credentials are unavailable. Remove them and enter them again.", null)
        }
    }
}
