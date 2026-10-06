package dev.zpasswd.app.data

import android.content.Context
import androidx.room.Room
import dev.zpasswd.app.crypto.ZpCrypto
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Instant
import java.util.UUID

/**
 * Vault 仓库：解锁状态、加解密、CRUD 的唯一入口。
 *
 * 安全铁律：
 * - 主密码/MK/DEK 只驻内存，lock() 时清零；
 * - 落盘的只有密文、salt、wrappedDek、JWT；
 * - 所有 Room 操作在 IO 线程。
 */
class VaultRepository private constructor(val db: ZpasswdDb) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val json = Json { ignoreUnknownKeys = true }

    /** 解锁态的 DEK（内存）。null = 已锁定。 */
    @Volatile
    private var dek: ByteArray? = null

    private val _unlocked = MutableStateFlow(false)
    val unlocked: StateFlow<Boolean> = _unlocked

    private val _items = MutableStateFlow<List<ItemWithPlain>>(emptyList())
    val items: StateFlow<List<ItemWithPlain>> = _items

    /** 是否已有 vault（meta 里有 salt） */
    suspend fun hasVault(): Boolean = withContext(Dispatchers.IO) {
        db.metaDao().get(KEY_SALT) != null
    }

    fun isUnlocked(): Boolean = _unlocked.value

    fun requireDek(): ByteArray = dek ?: throw IllegalStateException("vault 已锁定")

    /** 创建新 vault：生成 salt/DEK，用 MK 派生的 KEK 包裹 DEK 落盘。 */
    suspend fun createVault(password: String): Unit = withContext(Dispatchers.Default) {
        val salt = ZpCrypto.randomSalt()
        val mk = ZpCrypto.deriveMasterKey(password, salt)
        try {
            val kek = ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_ENC)
            try {
                val newDek = ZpCrypto.randomKey()
                val (nonceB64, sealedB64) = ZpCrypto.wrapDek(kek, newDek)
                withContext(Dispatchers.IO) {
                    db.metaDao().put(MetaEntity(KEY_SALT, ZpCrypto.b64encode(salt)))
                    db.metaDao().put(
                        MetaEntity(
                            KEY_WRAPPED_DEK,
                            json.encodeToString(WrappedDekJson(nonceB64, sealedB64)),
                        ),
                    )
                }
                setDek(newDek)
            } finally {
                ZpCrypto.wipe(kek)
            }
        } finally {
            ZpCrypto.wipe(mk)
        }
    }

    /** 主密码解锁。错密码时 unwrapDek 抛异常。 */
    suspend fun unlock(password: String): Unit = withContext(Dispatchers.Default) {
        val saltB64 = withContext(Dispatchers.IO) { db.metaDao().get(KEY_SALT) }
            ?: throw IllegalStateException("vault 不存在，请先创建")
        val wrapped = withContext(Dispatchers.IO) { db.metaDao().get(KEY_WRAPPED_DEK) }
            ?: throw IllegalStateException("vault 数据损坏")
        val wd = json.decodeFromString<WrappedDekJson>(wrapped)
        val mk = ZpCrypto.deriveMasterKey(password, ZpCrypto.b64decode(saltB64))
        try {
            val kek = ZpCrypto.deriveSubkey(mk, ZpCrypto.CTX_ENC)
            try {
                // 错主密码 → AEAD 认证失败抛异常，DEK 不会落盘
                val d = ZpCrypto.unwrapDek(kek, wd.nonce, wd.ciphertext)
                setDek(d)
            } finally {
                ZpCrypto.wipe(kek)
            }
        } finally {
            ZpCrypto.wipe(mk)
        }
    }

    /** 指纹快捷解锁：直接装入 DEK（调用方已通过 Keystore+指纹解密）。 */
    fun unlockWithDek(d: ByteArray) {
        setDek(d.copyOf())
    }

    fun currentDekCopy(): ByteArray = requireDek().copyOf()

    private fun setDek(d: ByteArray) {
        dek?.let { ZpCrypto.wipe(it) }
        dek = d
        _unlocked.value = true
        scope.launch { refreshItems() }
    }

    /** 锁定：清零内存密钥。 */
    fun lock() {
        dek?.let { ZpCrypto.wipe(it) }
        dek = null
        _unlocked.value = false
        _items.value = emptyList()
    }

    /** 换主密码：只重包 DEK，条目无需重加密。旧密码错误抛 IllegalArgumentException。 */
    suspend fun changePassword(oldPassword: String, newPassword: String): Unit =
        withContext(Dispatchers.Default) {
            val d = requireDek()
            // 用旧密码重新解包一次，失败即旧密码错误
            val saltB64 = withContext(Dispatchers.IO) { db.metaDao().get(KEY_SALT) }!!
            val wd = withContext(Dispatchers.IO) {
                json.decodeFromString<WrappedDekJson>(db.metaDao().get(KEY_WRAPPED_DEK)!!)
            }
            val oldMk = ZpCrypto.deriveMasterKey(oldPassword, ZpCrypto.b64decode(saltB64))
            try {
                val oldKek = ZpCrypto.deriveSubkey(oldMk, ZpCrypto.CTX_ENC)
                try {
                    ZpCrypto.wipe(ZpCrypto.unwrapDek(oldKek, wd.nonce, wd.ciphertext))
                } catch (_: IllegalArgumentException) {
                    throw IllegalArgumentException("旧主密码不正确")
                } finally {
                    ZpCrypto.wipe(oldKek)
                }
            } finally {
                ZpCrypto.wipe(oldMk)
            }
            // 旧密码正确，用新密码重包 DEK
            val newSalt = ZpCrypto.randomSalt()
            val newMk = ZpCrypto.deriveMasterKey(newPassword, newSalt)
            try {
                val newKek = ZpCrypto.deriveSubkey(newMk, ZpCrypto.CTX_ENC)
                try {
                    val (nonceB64, sealedB64) = ZpCrypto.wrapDek(newKek, d)
                    withContext(Dispatchers.IO) {
                        db.metaDao().put(MetaEntity(KEY_SALT, ZpCrypto.b64encode(newSalt)))
                        db.metaDao().put(
                            MetaEntity(
                                KEY_WRAPPED_DEK,
                                json.encodeToString(WrappedDekJson(nonceB64, sealedB64)),
                            ),
                        )
                    }
                } finally {
                    ZpCrypto.wipe(newKek)
                }
            } finally {
                ZpCrypto.wipe(newMk)
            }
        }

    // ---------- 条目 CRUD（调用方保证已解锁） ----------

    suspend fun refreshItems(): Unit = withContext(Dispatchers.IO) {
        val d = dek ?: return@withContext
        val entities = db.itemDao().allActive()
        _items.value = entities.mapNotNull { e ->
            try {
                val plain = json.decodeFromString<VaultItemPlain>(
                    ZpCrypto.decryptItem(d, e.nonce, e.ciphertext),
                )
                ItemWithPlain(e, plain)
            } catch (_: Exception) {
                null // 损坏条目跳过，不炸掉整个列表
            }
        }
    }

    suspend fun saveItem(
        id: String?,
        plain: VaultItemPlain,
        folderId: String?,
        favorite: Boolean,
    ): String = withContext(Dispatchers.IO) {
        val d = requireDek()
        val (nonceB64, ctB64) = ZpCrypto.encryptItem(d, json.encodeToString(plain))
        val now = Instant.now().toString()
        val existing = id?.let { db.itemDao().byId(it) }
        val entity = ItemEntity(
            id = id ?: UUID.randomUUID().toString(),
            nonce = nonceB64,
            ciphertext = ctB64,
            version = (existing?.version ?: 0) + 1,
            folderId = folderId,
            favorite = favorite,
            updatedAt = now,
            deletedAt = null,
            dirty = true,
        )
        db.itemDao().upsert(entity)
        refreshItems()
        entity.id
    }

    suspend fun deleteItem(id: String): Unit = withContext(Dispatchers.IO) {
        val e = db.itemDao().byId(id) ?: return@withContext
        db.itemDao().upsert(
            e.copy(
                version = e.version + 1,
                updatedAt = Instant.now().toString(),
                deletedAt = Instant.now().toString(),
                dirty = true,
            ),
        )
        refreshItems()
    }

    /** 供同步引擎：解密单个条目明文（冲突改名用）。 */
    fun decryptToPlain(entity: ItemEntity): VaultItemPlain {
        val d = requireDek()
        return json.decodeFromString(ZpCrypto.decryptItem(d, entity.nonce, entity.ciphertext))
    }

    /** 供同步引擎：明文加密为条目。 */
    fun encryptPlain(plain: VaultItemPlain): Pair<String, String> {
        return ZpCrypto.encryptItem(requireDek(), json.encodeToString(plain))
    }

    // ---------- meta / sync state ----------

    suspend fun getSaltB64(): String? = withContext(Dispatchers.IO) { db.metaDao().get(KEY_SALT) }
    suspend fun getWrappedDekJson(): WrappedDekJson? = withContext(Dispatchers.IO) {
        db.metaDao().get(KEY_WRAPPED_DEK)?.let { json.decodeFromString(it) }
    }

    suspend fun getSyncState(): SyncStateEntity? = withContext(Dispatchers.IO) {
        db.syncStateDao().get()
    }

    suspend fun saveSyncState(s: SyncStateEntity) = withContext(Dispatchers.IO) {
        db.syncStateDao().put(s)
    }

    suspend fun clearSyncState() = withContext(Dispatchers.IO) {
        db.syncStateDao().clear()
    }

    /** 导出加密备份（格式与扩展端 EXPORT 一致）。 */
    suspend fun exportBackup(): ExportBackup = withContext(Dispatchers.IO) {
        requireDek()
        val saltB64 = db.metaDao().get(KEY_SALT)!!
        val wd = json.decodeFromString<WrappedDekJson>(db.metaDao().get(KEY_WRAPPED_DEK)!!)
        val items = db.itemDao().allActive().map {
            ServerItem(it.id, it.nonce, it.ciphertext, it.version, it.folderId, it.favorite, it.updatedAt, it.deletedAt)
        }
        ExportBackup(
            exportedAt = Instant.now().toString(),
            saltB64 = saltB64,
            wrappedDek = wd,
            kdfParams = KdfParams(ZpCrypto.KDF_OPSLIMIT.toInt(), ZpCrypto.KDF_MEMLIMIT),
            items = items,
        )
    }

    /** 恢复出厂：清所有本地数据并锁定。 */
    suspend fun wipeAll(): Unit = withContext(Dispatchers.IO) {
        db.itemDao().clear()
        db.folderDao().clear()
        db.metaDao().clear()
        db.syncStateDao().clear()
        lock()
    }

    companion object {
        const val KEY_SALT = "salt"
        const val KEY_WRAPPED_DEK = "wrappedDek"
        const val KEY_BIOMETRIC_DEK = "biometricDek" // Keystore 加密后的 DEK
        const val KEY_IDLE_MINUTES = "idleMinutes"

        @Volatile
        private var instance: VaultRepository? = null

        fun get(context: Context): VaultRepository {
            return instance ?: synchronized(this) {
                instance ?: VaultRepository(
                    Room.databaseBuilder(context, ZpasswdDb::class.java, "zpasswd.db").build(),
                ).also { instance = it }
            }
        }
    }
}

data class ItemWithPlain(val entity: ItemEntity, val plain: VaultItemPlain)
