package dev.zpasswd.app.data

import androidx.room.*

@Entity(tableName = "items")
data class ItemEntity(
    @PrimaryKey val id: String,
    val nonce: String,
    val ciphertext: String,
    val version: Int,
    val folderId: String?,
    val favorite: Boolean,
    val updatedAt: String, // ISO
    val deletedAt: String?, // ISO，软删
    val dirty: Boolean = false, // 本地未同步标记，不上传
)

@Entity(tableName = "folders")
data class FolderEntity(
    @PrimaryKey val id: String,
    val name: String,
)

@Entity(tableName = "meta")
data class MetaEntity(
    @PrimaryKey val key: String,
    val value: String,
)

/** 单行同步状态（id 恒为 1） */
@Entity(tableName = "sync_state")
data class SyncStateEntity(
    @PrimaryKey val id: Int = 1,
    val serverUrl: String,
    val email: String,
    val deviceId: String,
    val deviceName: String,
    val accessJwt: String,
    val refreshJwt: String,
    val lastSyncAt: String, // ISO，空=从未同步
)

@Dao
interface ItemDao {
    @Query("SELECT * FROM items WHERE deletedAt IS NULL ORDER BY updatedAt DESC")
    suspend fun allActive(): List<ItemEntity>

    @Query("SELECT * FROM items WHERE id = :id")
    suspend fun byId(id: String): ItemEntity?

    @Query("SELECT * FROM items WHERE dirty = 1")
    suspend fun dirty(): List<ItemEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(item: ItemEntity)

    @Query("DELETE FROM items")
    suspend fun clear()
}

@Dao
interface FolderDao {
    @Query("SELECT * FROM folders ORDER BY name")
    suspend fun all(): List<FolderEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(folder: FolderEntity)

    @Query("DELETE FROM folders")
    suspend fun clear()
}

@Dao
interface MetaDao {
    @Query("SELECT value FROM meta WHERE `key` = :key")
    suspend fun get(key: String): String?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun put(meta: MetaEntity)

    @Query("DELETE FROM meta")
    suspend fun clear()
}

@Dao
interface SyncStateDao {
    @Query("SELECT * FROM sync_state WHERE id = 1")
    suspend fun get(): SyncStateEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun put(state: SyncStateEntity)

    @Query("DELETE FROM sync_state")
    suspend fun clear()
}

@Database(
    entities = [ItemEntity::class, FolderEntity::class, MetaEntity::class, SyncStateEntity::class],
    version = 1,
    exportSchema = false,
)
abstract class ZpasswdDb : androidx.room.RoomDatabase() {
    abstract fun itemDao(): ItemDao
    abstract fun folderDao(): FolderDao
    abstract fun metaDao(): MetaDao
    abstract fun syncStateDao(): SyncStateDao
}
