package dev.zpasswd.app.crypto

import java.security.MessageDigest

/**
 * BIP39 恢复码。与 @pm/crypto/src/recovery.ts 语义一致：
 * rec 子密钥（32B 熵）→ 24 词助记词；24 词 → 32B 熵。
 *
 * 算法（BIP39 标准）：
 * - 熵 256bit → SHA-256 取首字节为校验位（256/32=8bit）→ 264bit
 * - 每 11bit 一组 → 24 个词表索引
 */
object RecoveryCode {
    /** 32B 熵 → 24 词。 */
    fun entropyToMnemonic(entropy: ByteArray): String {
        require(entropy.size == 32) { "entropy must be 32 bytes" }
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)
        // 264 bits: entropy(256) + checksum 首 8bit
        val bits = StringBuilder(264)
        for (b in entropy) bits.append((b.toInt() and 0xFF).toString(2).padStart(8, '0'))
        bits.append((checksum[0].toInt() and 0xFF).toString(2).padStart(8, '0'))
        require(bits.length == 264)
        return (0 until 24).joinToString(" ") { i ->
            val idx = bits.substring(i * 11, i * 11 + 11).toInt(2)
            BIP39_WORDLIST[idx]
        }
    }

    /** 24 词 → 32B 熵；词非法/校验失败抛 IllegalArgumentException。 */
    fun mnemonicToEntropy(mnemonic: String): ByteArray {
        val words = mnemonic.trim().lowercase().split(Regex("\\s+"))
        require(words.size == 24) { "mnemonic must be 24 words" }
        val idx = words.map {
            val i = BIP39_WORDLIST.indexOf(it)
            require(i >= 0) { "unknown word: $it" }
            i
        }
        val bits = StringBuilder(264)
        for (i in idx) bits.append(i.toString(2).padStart(11, '0'))
        val entropy = ByteArray(32) { j ->
            bits.substring(j * 8, j * 8 + 8).toInt(2).toByte()
        }
        // 校验位
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)
        val expectedCs = (checksum[0].toInt() and 0xFF).toString(2).padStart(8, '0')
        val actualCs = bits.substring(256, 264)
        require(expectedCs == actualCs) { "checksum mismatch" }
        return entropy
    }

    fun isValid(mnemonic: String): Boolean = try {
        mnemonicToEntropy(mnemonic); true
    } catch (_: Exception) {
        false
    }

    /** 主密钥 → 24 词恢复码（经 rec 子密钥）。 */
    fun fromMasterKey(masterKey: ByteArray): String {
        val rec = ZpCrypto.deriveSubkey(masterKey, ZpCrypto.CTX_REC)
        return try {
            entropyToMnemonic(rec)
        } finally {
            ZpCrypto.wipe(rec)
        }
    }
}
