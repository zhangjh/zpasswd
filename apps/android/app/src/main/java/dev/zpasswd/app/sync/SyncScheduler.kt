package dev.zpasswd.app.sync

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import dev.zpasswd.app.biometric.DeviceAutoUnlock
import dev.zpasswd.app.data.MetaEntity
import dev.zpasswd.app.data.VaultRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.TimeUnit

/**
 * 自动同步调度。
 *
 * 背景：同步此前只由设置页的「立即同步」按钮、连接同步后、以及从服务器恢复后触发。
 * 新增 / 修改 / 删除条目只写本地并打上 dirty 标记，没有任何一处上传，
 * 于是服务端永远见不到这些条目 —— 换设备自然拉不到。
 * 现在把同步挂到四个时机：解锁后、每次本地写入后、定时兜底（WorkManager）、恢复后。
 *
 * 串行化：runSync 是「先拉后推 + version 乐观锁」。同一时刻跑两轮时，
 * 后一轮推送的 version 会被服务端判定为不更新而拒绝，客户端再把拒绝当冲突处理，
 * 于是凭空多出「冲突副本」。所以所有同步请求都排在同一把锁后面串行执行。
 *
 * 失败信息写在 meta[KEY_SYNC_ERROR]，供设置页展示；成功时清空。
 */
object SyncScheduler {
    private const val PERIODIC_WORK = "zpasswd-periodic-sync"
    private const val INTERVAL_MINUTES = 15L

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()

    /** 真正的同步体：未解锁 / 未连接同步时直接跳过，不产生任何网络请求。 */
    private suspend fun syncLocked(repo: VaultRepository): SyncResult {
        if (!repo.isUnlocked()) return SyncResult(skipped = true)
        val state = repo.getSyncState() ?: return SyncResult(skipped = true)
        if (state.serverUrl.isBlank()) return SyncResult(skipped = true)
        return SyncEngine(repo).runSync()
    }

    private suspend fun recordError(repo: VaultRepository, message: String) {
        runCatching { repo.db.metaDao().put(MetaEntity(VaultRepository.KEY_SYNC_ERROR, message)) }
    }

    private suspend fun clearError(repo: VaultRepository) {
        runCatching { repo.db.metaDao().put(MetaEntity(VaultRepository.KEY_SYNC_ERROR, "")) }
    }

    /** 手动同步：与自动同步共用同一把锁，错误抛给调用方展示。 */
    suspend fun syncNow(repo: VaultRepository): SyncResult {
        return try {
            val r = mutex.withLock { syncLocked(repo) }
            clearError(repo)
            r
        } catch (e: Exception) {
            recordError(repo, e.message ?: "同步失败")
            throw e
        }
    }

    /**
     * 本地写入后 / 解锁后触发同步。不阻塞调用方，失败只记进 meta ——
     * 本地写入已经成功，网络问题不该让「保存」看起来失败。
     */
    fun requestSync(repo: VaultRepository) {
        scope.launch { runSilently(repo) }
    }

    /** 静默同步一次（供 [SyncWorker] 与 [requestSync] 共用）。 */
    suspend fun runSilently(repo: VaultRepository) {
        try {
            mutex.withLock { syncLocked(repo) }
            clearError(repo)
        } catch (e: Exception) {
            recordError(repo, e.message ?: "同步失败")
        }
    }

    /**
     * 注册周期兜底同步。幂等：KEEP 策略保证重复调用不会重建任务、
     * 也就不会把周期一直重置（否则和 MV3 里无条件 create 闹钟是同一个坑）。
     */
    fun schedulePeriodic(context: Context) {
        val request = PeriodicWorkRequestBuilder<SyncWorker>(INTERVAL_MINUTES, TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build(),
            )
            .build()
        WorkManager.getInstance(context.applicationContext)
            .enqueueUniquePeriodicWork(PERIODIC_WORK, ExistingPeriodicWorkPolicy.KEEP, request)
    }
}

/**
 * 周期兜底同步。后台进程里 vault 通常是锁定态（DEK 只在内存），
 * 先尝试「设备免解锁」恢复解锁态；用户没开免解锁就跳过，不打扰用户。
 */
class SyncWorker(appContext: Context, params: WorkerParameters) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val repo = VaultRepository.get(applicationContext)
        if (!repo.isUnlocked()) {
            val ok = runCatching { DeviceAutoUnlock.tryUnlock(repo) }.getOrDefault(false)
            if (!ok) return Result.success()
        }
        // 失败留给下一个周期，不做退避重试，避免频繁唤醒
        SyncScheduler.runSilently(repo)
        return Result.success()
    }
}
