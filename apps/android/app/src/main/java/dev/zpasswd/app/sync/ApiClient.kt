package dev.zpasswd.app.sync

import dev.zpasswd.app.data.ServerItem
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

/**
 * 同步服务端 HTTP 客户端。契约与扩展端 sync.ts 顶部注释一致：
 * POST /v1/auth/signup {email, kdfSalt, authVerifier, wrappedDek:{nonce,ciphertext}}
 * POST /v1/auth/login {email, authKeyB64} -> {accessJwt, refreshJwt}（401 不区分账号存在性）
 * POST /v1/auth/refresh {refreshJwt} -> {accessJwt, refreshJwt?}
 * GET /v1/sync?since=ISO -> {items, serverTime}
 * PUT /v1/items/batch {items} -> {accepted[], rejected[{id, item}]}
 */
class ApiClient {
    @PublishedApi
    internal val json = Json { ignoreUnknownKeys = true }
    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()
    @PublishedApi
    internal val mt = "application/json".toMediaType()

    data class HttpResult(val code: Int, val body: String)

    /**
     * payload 必须用 reified 泛型：在调用处按实参的静态类型（LoginReq、
     * SignupReq 等 @Serializable 类）由编译器生成序列化器。
     * 若声明为 Any，运行时会报 "Serializer for class 'Any' is not found"。
     */
    @PublishedApi
    internal inline fun <reified T> encodeBody(payload: T): okhttp3.RequestBody =
        json.encodeToString(payload).toRequestBody(mt)

    inline fun <reified T> post(base: String, path: String, payload: T, token: String? = null): HttpResult {
        return exec(base, path, "POST", encodeBody(payload), token)
    }

    inline fun <reified T> put(base: String, path: String, payload: T, token: String): HttpResult {
        return exec(base, path, "PUT", encodeBody(payload), token)
    }

    fun get(base: String, path: String, token: String? = null): HttpResult {
        return exec(base, path, "GET", null, token)
    }

    @PublishedApi
    internal fun exec(
        base: String, path: String, method: String,
        body: okhttp3.RequestBody?, token: String?,
    ): HttpResult {
        val builder = Request.Builder().url(base + path)
        if (token != null) builder.header("Authorization", "Bearer $token")
        when (method) {
            "POST" -> builder.post(body!!)
            "PUT" -> builder.put(body!!)
            "GET" -> builder.get()
        }
        client.newCall(builder.build()).execute().use { res ->
            return HttpResult(res.code, res.body?.string() ?: "")
        }
    }

    fun <T> decode(body: String, deserializer: kotlinx.serialization.DeserializationStrategy<T>): T {
        return json.decodeFromJsonElement(deserializer, json.parseToJsonElement(body))
    }
}
