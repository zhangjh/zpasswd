package dev.zpasswd.app

import android.app.Application
import dev.zpasswd.app.biometric.DeviceAutoUnlock
import dev.zpasswd.app.data.VaultRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class ZpasswdApp : Application() {
    lateinit var repo: VaultRepository
        private set

    override fun onCreate() {
        super.onCreate()
        repo = VaultRepository.get(this)
        // 设备免解锁：进程一起（App 启动、自动填充服务被拉起、无障碍服务被拉起）就尝试
        // 恢复解锁态。放在这里是为了让所有入口共享同一份结果，避免各自重复解锁。
        // 未开启免解锁时 tryUnlock 立即返回 false，开销可忽略。
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            val unlocked = runCatching { DeviceAutoUnlock.tryUnlock(repo) }.getOrDefault(false)
            // 已经处于解锁态（同进程内此前解锁过）就顺手补登记一次：
            // 登记只在解锁成功那一刻做过一次，若那次失败（异常/进程被杀），
            // 这里能自愈，避免用户永远停在"每次填充都要解锁"。
            if (unlocked) runCatching { DeviceAutoUnlock.ensureEnrolled(repo) }
        }
    }
}
