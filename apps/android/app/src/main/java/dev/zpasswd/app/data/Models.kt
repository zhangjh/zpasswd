package dev.zpasswd.app.data

import kotlinx.serialization.Serializable

/** 解密后的条目明文（只在内存中存在，永不落盘） */
@Serializable
data class VaultItemPlain(
    val name: String = "",
    val username: String = "",
    val password: String = "",
    val url: String = "",
    val notes: String = "",
    val totpSeed: String = "",
)

const val CONFLICT_FOLDER_ID = "folder-conflict"
const val CONFLICT_FOLDER_NAME = "同步冲突"

/** 服务端条目（不透明密文，不含本地 dirty 标记） */
@Serializable
data class ServerItem(
    val id: String,
    val nonce: String,
    val ciphertext: String,
    val version: Int,
    val folderId: String?,
    val favorite: Boolean,
    val updatedAt: String,
    val deletedAt: String?,
)

/** 加密备份导出格式（与扩展端 EXPORT 一致） */
@Serializable
data class ExportBackup(
    val format: String = "zpasswd-export-v1",
    val exportedAt: String,
    val saltB64: String,
    val wrappedDek: WrappedDekJson,
    val kdfParams: KdfParams,
    val items: List<ServerItem>,
)

@Serializable
data class WrappedDekJson(val nonce: String, val ciphertext: String)

@Serializable
data class KdfParams(val opslimit: Int, val memlimit: Long)
