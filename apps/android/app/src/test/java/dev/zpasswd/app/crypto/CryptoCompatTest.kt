package dev.zpasswd.app.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test

/**
 * 与 @pm/crypto 的字节级兼容测试。
 * 向量来自 packages/crypto/test/vectors.json（固定 salt/nonce 的确定性向量）。
 * 若任一断言失败，说明 Android 端打不开扩展创建的 vault —— 必须修好，不许跳过。
 */
class CryptoCompatTest {

    companion object {
        lateinit var v: JSONObject

        @JvmStatic
        @BeforeClass
        fun setup() {
            ZpCrypto.injectForTest(LazySodiumJava(SodiumJava()))
            val text = Companion::class.java.getResource("/vectors.json")!!.readText()
            v = JSONObject(text)
        }

        fun hex(s: String): ByteArray {
            require(s.length % 2 == 0)
            return ByteArray(s.length / 2) { i ->
                s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }

        fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }

    @Test
    fun `kdf params are frozen`() {
        val kdf = v.getJSONObject("kdf")
        assertEquals(3, kdf.getInt("opslimit"))
        assertEquals(67108864, kdf.getInt("memlimit"))
        assertEquals("argon2id13", kdf.getString("alg"))
        assertEquals(3L, ZpCrypto.KDF_OPSLIMIT)
        assertEquals(67_108_864L, ZpCrypto.KDF_MEMLIMIT)
    }

    @Test
    fun `deriveMasterKey matches vector`() {
        val salt = hex(v.getString("salt_hex"))
        val mk = ZpCrypto.deriveMasterKey(v.getString("password"), salt)
        assertEquals(v.getString("masterKey_hex"), hexOf(mk))
    }

    @Test
    fun `subkeys match vectors`() {
        val mk = hex(v.getString("masterKey_hex"))
        assertEquals(v.getString("subkey_enc_hex"), hexOf(ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_ENC)))
        assertEquals(v.getString("subkey_auth_hex"), hexOf(ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_AUTH)))
        assertEquals(v.getString("subkey_rec_hex"), hexOf(ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_REC)))
    }

    @Test
    fun `aead fixed vector matches`() {
        val aead = v.getJSONObject("aead")
        val key = hex(aead.getString("key_hex"))
        val nonce = hex(aead.getString("nonce_hex"))
        val msg = aead.getString("plaintext").toByteArray(Charsets.UTF_8)
        // 直接调底层 sodium（固定 nonce），断言密文逐字节一致
        val sodium = ZpCrypto.sodium()
        val cipher = ByteArray(msg.size + 16)
        val clen = LongArray(1)
        val ok = sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(
            cipher, clen, msg, msg.size.toLong(), null, 0L, null, nonce, key,
        )
        assertTrue(ok)
        assertEquals(aead.getString("ciphertext_hex"), hexOf(cipher.copyOf(clen[0].toInt())))
        // 解密回环
        val plain = ByteArray(cipher.size - 16)
        val mlen = LongArray(1)
        val ok2 = sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(
            plain, mlen, null, cipher.copyOf(clen[0].toInt()), clen[0], null, 0L, nonce, key,
        )
        assertTrue(ok2)
        assertEquals(aead.getString("plaintext"), plain.copyOf(mlen[0].toInt()).toString(Charsets.UTF_8))
    }

    @Test
    fun `authVerifier matches vector`() {
        val authKey = hex(v.getString("subkey_auth_hex"))
        assertEquals(v.getString("authVerifier_b64"), ZpCrypto.makeAuthVerifier(authKey))
    }

    @Test
    fun `wrap unwrap roundtrip`() {
        val mk = ZpCrypto.deriveMasterKey("pw", ZpCrypto.randomSalt())
        val kek = ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_ENC)
        val dek = ZpCrypto.randomKey()
        val (nonceB64, sealedB64) = ZpCrypto.wrapDek(kek, dek)
        val back = ZpCrypto.unwrapDek(kek, nonceB64, sealedB64)
        assertArrayEquals(dek, back)
        try {
            ZpCrypto.unwrapDek(ZpCrypto.randomKey(), nonceB64, sealedB64)
            fail("wrong KEK must fail")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun `encrypt decrypt roundtrip and tamper detection`() {
        val dek = ZpCrypto.randomKey()
        val pt = """{"name":"GitHub","username":"alice"}"""
        val (n, c) = ZpCrypto.encryptItem(dek, pt)
        assertEquals(pt, ZpCrypto.decryptItem(dek, n, c))
        // 篡改密文必须失败
        val tampered = c.dropLast(4) + "AAAA"
        try {
            ZpCrypto.decryptItem(dek, n, tampered)
            fail("tampered ciphertext must fail")
        } catch (_: IllegalArgumentException) {
        }
        try {
            ZpCrypto.decryptItem(ZpCrypto.randomKey(), n, c)
            fail("wrong key must fail")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun `generator charset matches TS`() {
        // 与 generator.ts 的 buildCharset 逐字符一致（实测 81，TS 注释里的 80 是笔误）
        val cs = ZpCrypto.buildCharset(true, true, true, true, true)
        assertEquals(81, cs.length)
        assertFalse(cs.any { it in "0O1lI|`" })
        val full = ZpCrypto.buildCharset(true, true, true, true, false)
        assertEquals(86, full.length)
        val g = ZpCrypto.generatePassword()
        assertEquals(24, g.password.length)
        assertTrue(g.entropyBits >= 128)
        assertTrue(g.password.any { it.isUpperCase() })
        assertTrue(g.password.any { it.isLowerCase() })
        assertTrue(g.password.any { it.isDigit() })
    }

    @Test
    fun `recovery mnemonic roundtrip`() {
        val mk = ZpCrypto.deriveMasterKey("pw", ZpCrypto.randomSalt())
        val m1 = RecoveryCode.fromMasterKey(mk)
        val m2 = RecoveryCode.fromMasterKey(mk)
        assertEquals(m1, m2)
        assertEquals(24, m1.split(" ").size)
        assertTrue(RecoveryCode.isValid(m1))
        val rec = ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_REC)
        assertArrayEquals(rec, RecoveryCode.mnemonicToEntropy(m1))
        assertFalse(RecoveryCode.isValid("abandon abandon abandon"))
    }

    @Test
    fun `totp rfc6238 vector`() {
        // RFC 6238 附录 B：SHA-1, secret="12345678901234567890", T=59 → 94287082
        val secretB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        assertEquals("94287082", Totp.now(secretB32, digits = 8, timeMs = 59_000))
        assertEquals("07081804", Totp.now(secretB32, digits = 8, timeMs = 1111111109_000))
    }
}
