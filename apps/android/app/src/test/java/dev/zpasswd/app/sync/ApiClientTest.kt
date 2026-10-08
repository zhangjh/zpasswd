package dev.zpasswd.app.sync

import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 回归测试：ApiClient 必须按实参具体类型序列化请求体。
 * 曾用 `payload: Any` 导致运行时报 "Serializer for class 'Any' is not found"
 *（kotlinc 前端检查发现不了，只能靠运行时测试；沙箱禁 Java TCP，
 * 故只测序列化不测真实 HTTP）。
 */
class ApiClientTest {

    private fun bodyString(b: okhttp3.RequestBody): String {
        val buf = Buffer()
        b.writeTo(buf)
        return buf.readUtf8()
    }

    @Test
    fun `post serializes LoginReq`() {
        val s = bodyString(ApiClient().encodeBody(LoginReq("u@x.com", "QUJD")))
        assertTrue(s.contains("\"email\":\"u@x.com\""))
        assertTrue(s.contains("\"authKeyB64\":\"QUJD\""))
    }

    @Test
    fun `post serializes SignupReq`() {
        val s = bodyString(
            ApiClient().encodeBody(
                SignupReq(
                    "u@x.com", "c2FsdA==", "dmVyaWZpZXI=",
                    dev.zpasswd.app.data.WrappedDekJson("bm9uY2U=", "Y2lwaGVy"),
                ),
            ),
        )
        assertTrue(s.contains("\"kdfSalt\":\"c2FsdA==\""))
        assertTrue(s.contains("\"wrappedDek\""))
    }

    @Test
    fun `post serializes RefreshReq and put serializes BatchReq`() {
        val s1 = bodyString(ApiClient().encodeBody(RefreshReq("refresh-jwt")))
        assertTrue(s1.contains("\"refreshJwt\":\"refresh-jwt\""))
        val s2 = bodyString(ApiClient().encodeBody(BatchReq(emptyList())))
        assertEquals("{\"items\":[]}", s2)
    }

    @Test
    fun `decode parses LoginRes`() {
        val t = ApiClient().decode(
            """{"accessJwt":"a","refreshJwt":"r"}""",
            LoginRes.serializer(),
        )
        assertEquals("a", t.accessJwt)
        assertEquals("r", t.refreshJwt)
    }
}
