package dev.zpasswd.app.sync

import dev.zpasswd.app.crypto.ZpCrypto
import dev.zpasswd.app.data.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import java.time.Instant
import java.util.UUID

@Serializable
data class LoginReq(val email: String, val authKeyB64: String)

@Serializable
data class LoginRes(val accessJwt: String, val refreshJwt: String)

@Serializable
data class RefreshReq(val refreshJwt: String)

@Serializable
data class SignupReq(
    val email: String,
    val kdfSalt: String,
    val authVerifier: String,
    val wrappedDek: WrappedDekJson,
)

@Serializable
data class SyncRes(val items: List<ServerItem>, val serverTime: String)

@Serializable
data class BatchReq(val items: List<ServerItem>)

@Serializable
data class BatchRes(val accepted: List<String>, val rejected: List<RejectedItem>)

@Serializable
data class RejectedItem(val id: String, val item: ServerItem)

@Serializable
data class SaltRes(val kdfSalt: String, val wrappedDek: WrappedDekJson)

data class SyncResult(val skipped: Boolean = false, val pushed: Int = 0, val pulled: Int = 0, val conflicts: Int = 0)

/** 默认同步服务器（Cloudflare Workers 官方后端）；用户可在设置中改为自建地址 */
const val DEFAULT_SERVER_URL = "https://zpasswd-server.favlink.workers.dev"

/**
 * 同步引擎。逻辑与扩展端 sync.ts 的 runSync/connectSync 逐行对应。
 */
class SyncEngine(
    private val repo: VaultRepository,
    private val api: ApiClient = ApiClient(),
) {
    /** 带 refresh 重试的请求。401 时用 refreshJwt 换 token，重放一次。 */
    private suspend fun authed(
        state: SyncStateEntity,
        call: suspend (token: String) -> ApiClient.HttpResult,
    ): ApiClient.HttpResult = withContext(Dispatchers.IO) {
        var res = call(state.accessJwt)
        if (res.code == 401) {
            val r = api.post(state.serverUrl, "/v1/auth/refresh", RefreshReq(state.refreshJwt))
            if (r.code != 200) throw IllegalStateException("同步登录已过期，请在设置页重新连接同步服务")
            val t = api.decode(r.body, LoginRes.serializer())
            val updated = state.copy(
                accessJwt = t.accessJwt,
                refreshJwt = t.refreshJwt.ifEmpty { state.refreshJwt },
            )
            repo.saveSyncState(updated)
            res = call(updated.accessJwt)
        }
        res
    }

    /** 把本地冲突版本存一份副本到「同步冲突」文件夹（改名后重新加密）。 */
    private suspend fun stashConflict(local: ItemEntity) {
        repo.db.folderDao().upsert(FolderEntity(CONFLICT_FOLDER_ID, CONFLICT_FOLDER_NAME))
        val decrypted = repo.decryptToPlain(local)
        val plain = decrypted.copy(name = "${decrypted.name}（冲突副本）")
        val (nonceB64, ctB64) = repo.encryptPlain(plain)
        repo.db.itemDao().upsert(
            ItemEntity(
                id = UUID.randomUUID().toString(),
                nonce = nonceB64,
                ciphertext = ctB64,
                version = 1,
                folderId = CONFLICT_FOLDER_ID,
                favorite = false,
                updatedAt = Instant.now().toString(),
                deletedAt = null,
                dirty = true,
            ),
        )
    }

    suspend fun runSync(): SyncResult = withContext(Dispatchers.IO) {
        val state0 = repo.getSyncState()
            ?: return@withContext SyncResult(skipped = true)
        if (state0.serverUrl.isBlank()) return@withContext SyncResult(skipped = true)
        repo.requireDek()
        var state = state0
        val since = state.lastSyncAt.ifBlank { "1970-01-01T00:00:00.000Z" }

        // 1) 拉取增量
        val pullRes = authed(state) { token ->
            api.get(state.serverUrl, "/v1/sync?since=${java.net.URLEncoder.encode(since, "UTF-8")}", token)
        }
        // authed 可能已刷新 token，重读最新 state
        state = repo.getSyncState() ?: state
        if (pullRes.code != 200) throw IllegalStateException("同步拉取失败：HTTP ${pullRes.code}")
        val pull = api.decode(pullRes.body, SyncRes.serializer())
        var pulled = 0
        var conflicts = 0
        val itemDao = repo.db.itemDao()
        for (s in pull.items) {
            val local = itemDao.byId(s.id)
            if (local == null) {
                itemDao.upsert(s.toEntity(dirty = false))
                pulled++
            } else if (s.version > local.version) {
                if (local.dirty) {
                    stashConflict(local)
                    conflicts++
                }
                itemDao.upsert(s.toEntity(dirty = false))
                pulled++
            }
        }

        // 2) 推送本地变更（含删除 tombstone）
        val dirty = itemDao.dirty()
        var pushed = 0
        if (dirty.isNotEmpty()) {
            val pushRes = authed(state) { token ->
                api.put(state.serverUrl, "/v1/items/batch", BatchReq(dirty.map { it.toServer() }), token)
            }
            if (pushRes.code != 200) throw IllegalStateException("同步推送失败：HTTP ${pushRes.code}")
            val push = api.decode(pushRes.body, BatchRes.serializer())
            val accepted = push.accepted.toSet()
            for (item in dirty) {
                if (item.id in accepted) {
                    itemDao.byId(item.id)?.let { cur ->
                        itemDao.upsert(cur.copy(dirty = false))
                    }
                    pushed++
                }
            }
            for (r in push.rejected) {
                val local = itemDao.byId(r.id)
                if (local?.dirty == true) {
                    stashConflict(local)
                    conflicts++
                }
                itemDao.upsert(r.item.toEntity(dirty = false))
            }
        }

        state = repo.getSyncState()!!
        repo.saveSyncState(state.copy(lastSyncAt = pull.serverTime))
        repo.refreshItems()
        SyncResult(pushed = pushed, pulled = pulled, conflicts = conflicts)
    }

    /**
     * 连接同步服务：登录 → 401 则注册 → 再登录。
     * 需 vault 已解锁（取 MK 派生 authKey）。
     */
    suspend fun connectSync(
        serverUrl: String,
        email: String,
        deviceName: String,
        masterPassword: String,
    ): Unit = withContext(Dispatchers.IO) {
        val base = serverUrl.trim().trimEnd('/')
        require(base.startsWith("http://") || base.startsWith("https://")) {
            "服务器地址须以 http(s):// 开头"
        }
        repo.requireDek()
        // 派生 authKey（MK 只在内存）
        val saltB64 = repo.getSaltB64() ?: throw IllegalStateException("vault 不存在")
        val mk = ZpCrypto.deriveMasterKey(masterPassword, ZpCrypto.b64decode(saltB64))
        val authKey: ByteArray
        try {
            authKey = ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_AUTH)
        } finally {
            ZpCrypto.wipe(mk)
        }
        val authB64 = ZpCrypto.b64encode(authKey)
        try {
            fun doLogin() = api.post(base, "/v1/auth/login", LoginReq(email, authB64))

            var login = doLogin()
            if (login.code == 401) {
                // 服务端不区分账号不存在/密码错：尝试注册
                val wd = repo.getWrappedDekJson() ?: throw IllegalStateException("vault 数据损坏")
                val reg = api.post(
                    base, "/v1/auth/signup",
                    SignupReq(email, saltB64, ZpCrypto.makeAuthVerifier(authKey), wd),
                )
                if (reg.code != 200 && reg.code != 201) {
                    throw IllegalStateException("注册失败：HTTP ${reg.code}")
                }
                login = doLogin()
            }
            if (login.code != 200) {
                throw IllegalStateException("登录失败：该邮箱已注册但主密码不正确，或服务器地址有误")
            }
            val t = api.decode(login.body, LoginRes.serializer())
            val prev = repo.getSyncState()
            repo.saveSyncState(
                SyncStateEntity(
                    serverUrl = base,
                    email = email,
                    deviceId = prev?.deviceId ?: UUID.randomUUID().toString(),
                    deviceName = deviceName,
                    accessJwt = t.accessJwt,
                    refreshJwt = t.refreshJwt,
                    lastSyncAt = prev?.lastSyncAt ?: "",
                ),
            )
        } finally {
            ZpCrypto.wipe(authKey)
        }
    }

    suspend fun disconnect() {
        repo.clearSyncState()
    }

    /**
     * 从服务器恢复：重装/换机后，用邮箱+主密码取回服务器上的 salt/wrappedDek，
     * 覆盖本地 vault，然后拉取条目。逻辑与扩展端恢复流程一致。
     * 成功后 vault 处于解锁态且已保存同步配置。
     */
    suspend fun restoreFromServer(
        serverUrl: String,
        email: String,
        deviceName: String,
        masterPassword: String,
    ): Unit = withContext(Dispatchers.IO) {
        val base = serverUrl.trim().trimEnd('/')
        require(base.startsWith("http://") || base.startsWith("https://")) {
            "服务器地址须以 http(s):// 开头"
        }
        require(email.isNotBlank()) { "请输入邮箱" }
        require(masterPassword.isNotEmpty()) { "请输入主密码" }

        // 1) 取服务器 salt（不存在返回 404）
        val saltRes = api.get(
            base,
            "/v1/auth/salt?email=${java.net.URLEncoder.encode(email.trim(), "UTF-8")}",
        )
        if (saltRes.code == 404) throw IllegalStateException("该邮箱没有同步账号")
        if (saltRes.code != 200) throw IllegalStateException("获取服务器数据失败：HTTP ${saltRes.code}")
        val sr = api.decode(saltRes.body, SaltRes.serializer())

        // 2) 用旧 salt 派生 authKey 并登录验证（主密码错误 → 登录失败）
        val mk = ZpCrypto.deriveMasterKey(masterPassword, ZpCrypto.b64decode(sr.kdfSalt))
        val authKey: ByteArray
        try {
            authKey = ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_AUTH)
        } finally {
            ZpCrypto.wipe(mk)
        }
        try {
            val login = api.post(base, "/v1/auth/login", LoginReq(email.trim(), ZpCrypto.b64encode(authKey)))
            if (login.code != 200) throw IllegalStateException("主密码不正确")
            val t = api.decode(login.body, LoginRes.serializer())

            // 3) 覆盖本地 vault 并解锁
            repo.installServerVault(sr.kdfSalt, sr.wrappedDek)
            repo.unlock(masterPassword)
            repo.saveSyncState(
                SyncStateEntity(
                    serverUrl = base,
                    email = email.trim(),
                    deviceId = UUID.randomUUID().toString(),
                    deviceName = deviceName,
                    accessJwt = t.accessJwt,
                    refreshJwt = t.refreshJwt,
                    lastSyncAt = "",
                ),
            )
        } finally {
            ZpCrypto.wipe(authKey)
        }
    }

    private fun ServerItem.toEntity(dirty: Boolean) = ItemEntity(
        id = id, nonce = nonce, ciphertext = ciphertext, version = version,
        folderId = folderId, favorite = favorite, updatedAt = updatedAt,
        deletedAt = deletedAt, dirty = dirty,
    )

    private fun ItemEntity.toServer() = ServerItem(
        id = id, nonce = nonce, ciphertext = ciphertext, version = version,
        folderId = folderId, favorite = favorite, updatedAt = updatedAt, deletedAt = deletedAt,
    )
}
