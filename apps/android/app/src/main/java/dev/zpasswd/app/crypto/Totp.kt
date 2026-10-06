package dev.zpasswd.app.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

/**
 * TOTP（RFC 6238 / RFC 4226），SHA-1，默认 6 位 / 30 秒。
 * 与扩展端 src/lib/totp.ts 语义一致。
 */
object Totp {
    /** 手写 base32 解码（RFC 4648，不含 padding 也可）。 */
    fun base32Decode(s: String): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val clean = s.trim().replace("=", "").uppercase()
        require(clean.all { it in alphabet }) { "invalid base32" }
        val out = ByteArray((clean.length * 5) / 8)
        var buffer = 0
        var bitsLeft = 0
        var count = 0
        for (c in clean) {
            buffer = (buffer shl 5) or alphabet.indexOf(c)
            bitsLeft += 5
            if (bitsLeft >= 8) {
                out[count++] = ((buffer shr (bitsLeft - 8)) and 0xFF).toByte()
                bitsLeft -= 8
            }
        }
        return out.copyOf(count)
    }

    /** 当前时间点的 TOTP 码。timeMs 可注入（测试用）。 */
    fun now(secretB32: String, digits: Int = 6, periodSec: Long = 30, timeMs: Long = System.currentTimeMillis()): String {
        val key = base32Decode(secretB32)
        val counter = timeMs / 1000 / periodSec
        val msg = ByteArray(8)
        for (i in 0 until 8) msg[7 - i] = ((counter ushr (i * 8)) and 0xFF).toByte()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        val hash = mac.doFinal(msg)
        val offset = (hash.last().toInt() and 0x0F)
        val code = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        val mod = 10.0.pow(digits).toInt()
        return (code % mod).toString().padStart(digits, '0')
    }

    /** 距下次轮换的秒数（UI 倒计时用）。 */
    fun secondsRemaining(periodSec: Long = 30, timeMs: Long = System.currentTimeMillis()): Long {
        return periodSec - ((timeMs / 1000) % periodSec)
    }
}
