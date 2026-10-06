package dev.zpasswd.app

import android.app.Application
import android.os.SystemClock
import dev.zpasswd.app.data.VaultRepository
import kotlinx.coroutines.*

/**
 * 空闲自动锁定：App 切后台时记时间，回到前台时若超过设定分钟数则 lock()。
 * 分钟数存在 meta[KEY_IDLE_MINUTES]，默认 5，0 = 不自动锁定。
 */
object IdleLock {
    private var backgroundAt: Long = 0

    fun onBackground() {
        backgroundAt = SystemClock.elapsedRealtime()
    }

    fun onForeground(repo: VaultRepository) {
        if (backgroundAt == 0L) return
        val elapsedMin = (SystemClock.elapsedRealtime() - backgroundAt) / 60_000
        backgroundAt = 0
        if (!repo.isUnlocked()) return
        CoroutineScope(Dispatchers.IO).launch {
            val minutes = repo.db.metaDao().get(VaultRepository.KEY_IDLE_MINUTES)
                ?.toLongOrNull() ?: 5L
            if (minutes > 0 && elapsedMin >= minutes) {
                repo.lock()
            }
        }
    }
}
