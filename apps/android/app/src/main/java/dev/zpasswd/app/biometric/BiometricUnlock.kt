package dev.zpasswd.app.biometric

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dev.zpasswd.app.crypto.ZpCrypto
import dev.zpasswd.app.data.MetaEntity
import dev.zpasswd.app.data.VaultRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 指纹快捷解锁：Android Keystore 生成 AES 密钥（setUserAuthenticationRequired），
 * 用它加密 DEK 后存 meta。所有加解密都经 BiometricPrompt.CryptoObject，
 * 指纹验证与密钥使用原子绑定，不存在"先验指纹后解密"的绕过窗口。
 *
 * 首次开启必须在主密码解锁后手动操作。
 */
object BiometricUnlock {
    private const val KEY_ALIAS = "zpasswd_biometric_dek"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    fun isAvailable(context: android.content.Context): Boolean {
        val mgr = BiometricManager.from(context)
        return mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let {
            return it.secretKey
        }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                // 录入新指纹后密钥失效（防绕过）
                .setInvalidatedByBiometricEnrollment(true)
                .build(),
        )
        return kg.generateKey()
    }

    private fun promptInfo(title: String) = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle("验证指纹以继续")
        .setNegativeButtonText("取消")
        .build()

    /**
     * 开启指纹解锁：弹窗验指纹 → 用 CryptoObject 加密当前 DEK → 存 meta。
     * 调用时 vault 须已用主密码解锁。
     */
    fun enroll(
        activity: FragmentActivity,
        repo: VaultRepository,
        onDone: () -> Unit,
        onError: (String) -> Unit,
    ) {
        val cipher = try {
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            }
        } catch (e: Exception) {
            onError(e.message ?: "初始化失败"); return
        }
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c == null) { onError("认证对象丢失"); return }
                    val dek = repo.currentDekCopy()
                    try {
                        val iv = c.iv
                        val sealed = c.doFinal(dek)
                        val stored = ZpCrypto.b64encode(iv) + "." + ZpCrypto.b64encode(sealed)
                        CoroutineScope(Dispatchers.IO).launch {
                            try {
                                repo.db.metaDao().put(MetaEntity(VaultRepository.KEY_BIOMETRIC_DEK, stored))
                                withContext(Dispatchers.Main) { onDone() }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) { onError(e.message ?: "保存失败") }
                            }
                        }
                    } catch (e: Exception) {
                        onError(e.message ?: "加密失败")
                    } finally {
                        ZpCrypto.wipe(dek)
                    }
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    onError(msg.toString())
                }
            },
        )
        prompt.authenticate(promptInfo("开启指纹解锁"), BiometricPrompt.CryptoObject(cipher))
    }

    suspend fun isEnrolled(repo: VaultRepository): Boolean =
        withContext(Dispatchers.IO) {
            !repo.db.metaDao().get(VaultRepository.KEY_BIOMETRIC_DEK).isNullOrEmpty()
        }

    suspend fun clear(repo: VaultRepository) = withContext(Dispatchers.IO) {
        repo.db.metaDao().put(MetaEntity(VaultRepository.KEY_BIOMETRIC_DEK, ""))
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            ks.deleteEntry(KEY_ALIAS)
        } catch (_: Exception) {
        }
    }

    /**
     * 指纹解锁：读 meta 取 IV → Cipher(DECRYPT) → CryptoObject 弹窗 →
     * 成功后直接解密 DEK 并解锁 vault。
     */
    fun authenticate(
        activity: FragmentActivity,
        repo: VaultRepository,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        CoroutineScope(Dispatchers.IO).launch {
            val stored = repo.db.metaDao().get(VaultRepository.KEY_BIOMETRIC_DEK)
            if (stored.isNullOrEmpty()) {
                withContext(Dispatchers.Main) { onError("未开启指纹解锁") }
                return@launch
            }
            val cipher = try {
                val ivB64 = stored.substringBefore(".")
                val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                val key = (ks.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
                Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, ZpCrypto.b64decode(ivB64)))
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { onError(e.message ?: "初始化失败") }
                return@launch
            }
            withContext(Dispatchers.Main) {
                val executor = ContextCompat.getMainExecutor(activity)
                val prompt = BiometricPrompt(
                    activity, executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val c = result.cryptoObject?.cipher
                            if (c == null) { onError("认证对象丢失"); return }
                            try {
                                val sealed = ZpCrypto.b64decode(stored.substringAfter("."))
                                val dek = c.doFinal(sealed)
                                repo.unlockWithDek(dek)
                                ZpCrypto.wipe(dek)
                                onSuccess()
                            } catch (e: Exception) {
                                onError(e.message ?: "解密失败")
                            }
                        }

                        override fun onAuthenticationError(code: Int, msg: CharSequence) {
                            onError(msg.toString())
                        }
                    },
                )
                prompt.authenticate(promptInfo("解锁 zpasswd"), BiometricPrompt.CryptoObject(cipher))
            }
        }
    }

}
