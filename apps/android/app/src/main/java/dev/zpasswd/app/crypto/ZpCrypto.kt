package dev.zpasswd.app.crypto

import java.util.Base64
import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.PwHash
import com.goterl.lazysodium.utils.Key
import com.sun.jna.NativeLong
import java.security.SecureRandom

/**
 * zpasswd 密码学核心。与 @pm/crypto（TypeScript/libsodium）字节级兼容。
 *
 * 冻结参数（与 packages/crypto/src/kdf.ts 一致，修改需人工 review）：
 * - KDF: Argon2id, opslimit=3, memlimit=64MiB, salt 16B → 32B 主密钥
 * - 子密钥: crypto_kdf_derive_from_key(32, id=1, context8, mk)
 *   enc="PMENCv10", auth="PMAUTHv1", rec="PMRECv10"（恰好 8 字节）
 * - 条目: XChaCha20-Poly1305 (ietf), 每条目随机 24B nonce
 * - base64: 标准带 padding（= libsodium ORIGINAL = Android Base64.DEFAULT）
 * - authVerifier: SHA-256(authKey bytes) → base64（不是 Argon2，见服务端注释：
 *   authKey 是 256 位随机密钥，原像抗性足够；Workers CPU 时限跑不动 Argon2）
 */
object ZpCrypto {
    const val KDF_OPSLIMIT = 3L
    const val KDF_MEMLIMIT = 67_108_864L // 64 MiB
    const val SALT_BYTES = 16
    const val KEY_BYTES = 32
    const val NONCE_BYTES = 24
    const val MAC_BYTES = 16

    const val CTX_ENC = "PMENCv10"
    const val CTX_AUTH = "PMAUTHv1"
    const val CTX_REC = "PMRECv10"

    @Volatile
    private var lazySodium: LazySodium? = null

    /** 线程安全的懒初始化（Android 上加载 .so）。 */
    fun sodium(): LazySodium {
        return lazySodium ?: synchronized(this) {
            lazySodium ?: LazySodiumAndroid(SodiumAndroid()).also { lazySodium = it }
        }
    }

    /** JVM 单元测试用：允许注入桌面版 LazySodium（lazysodium-java）。 */
    fun injectForTest(ls: LazySodium) {
        lazySodium = ls
    }

    fun b64encode(b: ByteArray): String =
        Base64.getEncoder().encodeToString(b)

    fun b64decode(s: String): ByteArray =
        Base64.getMimeDecoder().decode(s.trim())

    fun randomSalt(): ByteArray = sodium().randomBytesBuf(SALT_BYTES)

    fun randomKey(): ByteArray = sodium().randomBytesBuf(KEY_BYTES)

    fun randomNonce(): ByteArray = sodium().randomBytesBuf(NONCE_BYTES)

    /** 主密码(UTF-8) → 32B 主密钥。手机上约 1-2 秒，调用方自行放后台线程。 */
    fun deriveMasterKey(password: String, salt: ByteArray): ByteArray {
        require(salt.size == SALT_BYTES) { "salt must be $SALT_BYTES bytes" }
        val pw = password.toByteArray(Charsets.UTF_8)
        val out = ByteArray(KEY_BYTES)
        val ok = sodium().cryptoPwHash(
            out, KEY_BYTES, pw, pw.size, salt,
            KDF_OPSLIMIT, NativeLong(KDF_MEMLIMIT), PwHash.Alg.PWHASH_ALG_ARGON2ID13,
        )
        sodium().sodiumMemZero(pw, pw.size)
        require(ok) { "crypto_pwhash failed" }
        return out
    }

    /** MK → 用途子密钥。 */
    fun deriveSubkey(masterKey: ByteArray, context8: String): ByteArray {
        require(masterKey.size == KEY_BYTES) { "masterKey must be 32 bytes" }
        require(context8.toByteArray(Charsets.US_ASCII).size == 8) { "context must be 8 bytes" }
        return sodium().cryptoKdfDeriveFromKey(
            KEY_BYTES, 1L, context8, Key.fromBytes(masterKey),
        ).asBytes
    }

    /** 用 KEK 包裹 DEK（换主密码时只重包 DEK）。返回 Pair(nonceB64, sealedB64)。 */
    fun wrapDek(kek: ByteArray, dek: ByteArray): Pair<String, String> {
        val nonce = randomNonce()
        val sealed = aeadEncrypt(dek, nonce, kek)
        return b64encode(nonce) to b64encode(sealed)
    }

    fun unwrapDek(kek: ByteArray, nonceB64: String, sealedB64: String): ByteArray {
        val nonce = b64decode(nonceB64)
        val sealed = b64decode(sealedB64)
        return aeadDecrypt(sealed, nonce, kek)
            ?: throw IllegalArgumentException("unwrapDek failed: wrong KEK or tampered data")
    }

    /** 条目加密：明文 JSON → (nonceB64, ciphertextB64)。 */
    fun encryptItem(dek: ByteArray, plaintext: String): Pair<String, String> {
        val nonce = randomNonce()
        val ct = aeadEncrypt(plaintext.toByteArray(Charsets.UTF_8), nonce, dek)
        return b64encode(nonce) to b64encode(ct)
    }

    /** 条目解密：篡改/错 key 抛 IllegalArgumentException。 */
    fun decryptItem(dek: ByteArray, nonceB64: String, ciphertextB64: String): String {
        val pt = aeadDecrypt(b64decode(ciphertextB64), b64decode(nonceB64), dek)
            ?: throw IllegalArgumentException("decryptItem failed: wrong key or tampered data")
        return pt.toString(Charsets.UTF_8)
    }

    private fun aeadEncrypt(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        require(nonce.size == NONCE_BYTES && key.size == KEY_BYTES)
        val cipher = ByteArray(message.size + MAC_BYTES)
        val clen = LongArray(1)
        val ok = sodium().cryptoAeadXChaCha20Poly1305IetfEncrypt(
            cipher, clen, message, message.size.toLong(), null, 0L, null, nonce, key,
        )
        require(ok) { "aead encrypt failed" }
        return cipher.copyOf(clen[0].toInt())
    }

    private fun aeadDecrypt(cipher: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray? {
        if (nonce.size != NONCE_BYTES || key.size != KEY_BYTES || cipher.size < MAC_BYTES) return null
        val plain = ByteArray(cipher.size - MAC_BYTES)
        val mlen = LongArray(1)
        val ok = sodium().cryptoAeadXChaCha20Poly1305IetfDecrypt(
            plain, mlen, null, cipher, cipher.size.toLong(), null, 0L, nonce, key,
        )
        if (!ok) return null
        return plain.copyOf(mlen[0].toInt())
    }

    /** authVerifier = base64(SHA-256(authKey))。 */
    fun makeAuthVerifier(authKey: ByteArray): String {
        require(authKey.size == KEY_BYTES)
        val digest = ByteArray(32)
        val ok = sodium().cryptoHashSha256(digest, authKey, authKey.size.toLong())
        require(ok)
        return b64encode(digest)
    }

    /** 恒定时间比较两个等长数组。 */
    fun memcmp(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    /** 清零敏感内存。 */
    fun wipe(b: ByteArray) {
        sodium().sodiumMemZero(b, b.size)
    }

    private val secureRandom = SecureRandom()

    /**
     * CSPRNG 密码生成，拒绝采样消除模偏差。
     * 字符集与 @pm/crypto/src/generator.ts 完全一致。
     */
    fun generatePassword(
        length: Int = 24,
        uppercase: Boolean = true,
        lowercase: Boolean = true,
        digits: Boolean = true,
        symbols: Boolean = true,
        excludeSimilar: Boolean = true,
    ): GeneratedPassword {
        require(length in 8..128)
        val charset = buildCharset(uppercase, lowercase, digits, symbols, excludeSimilar)
        require(charset.isNotEmpty())
        val n = charset.length
        val limit = 256 - (256 % n)
        fun pick(): Char {
            while (true) {
                val b = ByteArray(1).also { secureRandom.nextBytes(it) }[0].toInt() and 0xFF
                if (b < limit) return charset[b % n]
            }
        }
        val groups = mutableListOf<String>()
        if (uppercase) groups += UPPER
        if (lowercase) groups += LOWER
        if (digits) groups += DIGITS
        if (symbols) groups += SYMBOLS
        val chars = ArrayList<Char>(length)
        for (g in groups) {
            val f = g.filter { charset.contains(it) }
            chars += f[secureRandom.nextInt(f.length)]
        }
        while (chars.size < length) chars += pick()
        // Fisher-Yates
        for (i in chars.size - 1 downTo 1) {
            val j = secureRandom.nextInt(i + 1)
            val t = chars[i]; chars[i] = chars[j]; chars[j] = t
        }
        val password = chars.joinToString("")
        val entropyBits = length * (kotlin.math.log2(n.toDouble()))
        return GeneratedPassword(password, entropyBits, n)
    }

    const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    const val LOWER = "abcdefghijkmnopqrstuvwxyz"
    const val DIGITS = "23456789"
    const val SYMBOLS = "!@#\$%^&*()-_=+[]{};:,.<>?"
    private val SIMILAR = setOf('0', 'O', 'o', '1', 'l', 'I', '|', '`')

    fun buildCharset(
        uppercase: Boolean, lowercase: Boolean, digits: Boolean,
        symbols: Boolean, excludeSimilar: Boolean,
    ): String {
        val sb = StringBuilder()
        if (uppercase) sb.append(UPPER)
        if (lowercase) sb.append(LOWER)
        if (digits) sb.append(DIGITS)
        if (symbols) sb.append(SYMBOLS)
        if (!excludeSimilar) {
            if (uppercase) sb.append("IO")
            if (lowercase) sb.append("lo")
            if (digits) sb.append("01")
        }
        val dedup = sb.toString().toSet()
        return dedup.filter { !excludeSimilar || it !in SIMILAR }.joinToString("")
    }
}

data class GeneratedPassword(
    val password: String,
    val entropyBits: Double,
    val charsetSize: Int,
)
