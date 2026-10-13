package dev.zpasswd.app.biometric

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.zpasswd.app.autofill.AutofillDiag
import dev.zpasswd.app.crypto.ZpCrypto
import dev.zpasswd.app.data.MetaEntity
import dev.zpasswd.app.data.VaultRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 设备免解锁：把 DEK 用 Android Keystore 里一把**不要求用户认证**的 AES 密钥再包一层，
 * 密文存 meta。App / 自动填充服务启动时自动解包 → vault 直接是解锁态，
 * 用户不需要每次填充前先输主密码。
 *
 * ## 和「指纹解锁」的区别
 *
 * [BiometricUnlock] 的 Keystore 密钥是 `setUserAuthenticationRequired(true)`，
 * 每次用都要过指纹，密钥使用与指纹验证原子绑定。
 * 本对象刻意**不要求认证**，代价是：
 *
 * - 好处：进程重启后能自动恢复解锁态，填充/查看都不用再验证；
 * - 代价：**拿到已解锁手机的人可以直接打开 zpasswd 看密码**。
 *
 * ## 安全边界（没有变的部分）
 *
 * - DEK 依旧不落明文：落盘的是 Keystore 密钥加密后的密文；
 * - Keystore 密钥绑定本机、绑定本应用 uid，别的 App 拿不到也导不出；
 * - 换机 / 清应用数据后密文无法解开，仍需主密码。
 *
 * 想要「锁屏即保护」的用户可以在 设置 → 免解锁 里关掉，回到主密码 / 指纹解锁。
 */
object DeviceAutoUnlock {
    private const val KEY_ALIAS = "zpasswd_device_dek"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128

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
                // 关键：不要求指纹/锁屏验证，否则进程重启后没法自动解包
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return kg.generateKey()
    }

    /** 是否已开启免解锁（meta 里有 DEK 密文）。 */
    suspend fun isEnrolled(repo: VaultRepository): Boolean = withContext(Dispatchers.IO) {
        !repo.db.metaDao().get(VaultRepository.KEY_DEVICE_DEK).isNullOrEmpty()
    }

    /**
     * 用当前 DEK 生成免解锁密文。幂等：已存在时直接返回 true，不重复包。
     * 由 [VaultRepository.setDek] 在每次解锁成功后调用，所以用户无感。
     */
    suspend fun ensureEnrolled(repo: VaultRepository): Boolean = withContext(Dispatchers.IO) {
        if (isEnrolled(repo)) return@withContext true
        val dek = try {
            repo.currentDekCopy()
        } catch (_: Exception) {
            // 还没解锁：正常路径（例如进程刚起来），不打日志免得刷屏
            return@withContext false
        }
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            }
            val sealed = cipher.doFinal(dek)
            val stored = ZpCrypto.b64encode(cipher.iv) + "." + ZpCrypto.b64encode(sealed)
            repo.db.metaDao().put(MetaEntity(VaultRepository.KEY_DEVICE_DEK, stored))
            AutofillDiag.log("免解锁：已登记 DEK 密文（此后填充不再要求解锁）")
            true
        } catch (e: Exception) {
            // 登记失败必须留痕，否则用户只会看到"每次都要解锁"却查不出原因
            AutofillDiag.log("免解锁：登记失败 ${e.javaClass.simpleName}: ${e.message}")
            false
        } finally {
            ZpCrypto.wipe(dek)
        }
    }

    /**
     * 自动解锁。已解锁时直接返回 true；未开启免解锁、或密文解不开（换机 / 密钥被清）返回 false。
     *
     * @param quiet 未登记时是否静默。默认 true——启动路径每次都会调用，不登记就刷屏了；
     *   由"用户主动触发"的路径（如无障碍面板）传 false，好让日志说清为什么又要求解锁。
     */
    suspend fun tryUnlock(repo: VaultRepository, quiet: Boolean = true): Boolean =
        withContext(Dispatchers.IO) {
            if (repo.isUnlocked()) return@withContext true
            val stored = repo.db.metaDao().get(VaultRepository.KEY_DEVICE_DEK)
            if (stored.isNullOrEmpty()) {
                // 尚未登记：需要用户先用主密码/指纹解锁一次，之后才会自动生效。
                if (!quiet) AutofillDiag.log("免解锁：尚未登记，请先解锁一次 zpasswd")
                return@withContext false
            }
            try {
                val ivB64 = stored.substringBefore(".")
                val sealedB64 = stored.substringAfter(".")
                val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
                val key = (ks.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
                val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                    init(
                        Cipher.DECRYPT_MODE,
                        key,
                        GCMParameterSpec(GCM_TAG_BITS, ZpCrypto.b64decode(ivB64)),
                    )
                }
                val dek = cipher.doFinal(ZpCrypto.b64decode(sealedB64))
                repo.unlockWithDek(dek)
                ZpCrypto.wipe(dek)
                true
            } catch (e: Exception) {
                // 解不开（换机、Keystore 被清、数据损坏）→ 回到主密码解锁，但必须留痕，
                // 否则用户只会看到"每次都要解锁"而查不出原因。
                AutofillDiag.log("免解锁：解密失败 ${e.javaClass.simpleName}: ${e.message}")
                false
            }
        }

    /** 关闭免解锁：删掉密文与 Keystore 密钥。 */
    suspend fun disable(repo: VaultRepository) = withContext(Dispatchers.IO) {
        repo.db.metaDao().put(MetaEntity(VaultRepository.KEY_DEVICE_DEK, ""))
        runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(KEY_ALIAS)
        }
        AutofillDiag.log("免解锁：已关闭，填充前需要解锁")
    }
}
