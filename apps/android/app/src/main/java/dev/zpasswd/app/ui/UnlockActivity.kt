package dev.zpasswd.app.ui

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import dev.zpasswd.app.ZpasswdApp
import dev.zpasswd.app.autofill.ZpasswdAutofillService
import dev.zpasswd.app.biometric.DeviceAutoUnlock
import dev.zpasswd.app.data.VaultRepository
import kotlinx.coroutines.launch

/**
 * 解锁页。两种模式：
 * - 普通：App 内解锁，成功后 finish（MainActivity 会自己跳转）。
 * - Autofill 认证（EXTRA_AUTOFILL_MODE=true）：由 AutofillService 的 PendingIntent 拉起，
 *   解锁成功后把 FillResponse 塞进 EXTRA_AUTHENTICATION_RESULT 返回给系统。
 *
 * 这里**不再持有 AutofillService 实例引用**：service 可能在用户解锁期间被系统回收，
 * 依赖实例会导致解锁后拿不到响应（表现为解锁页一闪而过、什么都没填）。
 * 表单暂存在 ZpasswdAutofillService.PendingAuth（进程级），响应由 companion 直接重建。
 */
class UnlockActivity : FragmentActivity() {
    companion object {
        const val EXTRA_AUTOFILL_MODE = "autofill_mode"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val repo = (application as ZpasswdApp).repo
        val autofillMode = intent.getBooleanExtra(EXTRA_AUTOFILL_MODE, false)
        // 开了设备免解锁时这里根本不该出现：先尝试自动解包 DEK，成功就直接结束，
        // 连解锁页都不渲染（否则会闪一下）。
        lifecycleScope.launch {
            val auto = runCatching { DeviceAutoUnlock.tryUnlock(repo) }.getOrDefault(false)
            if (auto) {
                if (autofillMode) finishWithFillResponse() else finish()
            } else {
                showUnlockUi(repo, autofillMode)
            }
        }
    }

    private fun showUnlockUi(repo: VaultRepository, autofillMode: Boolean) {
        setContent {
            MaterialTheme {
                UnlockScreen(
                    activity = this,
                    repo = repo,
                    onUnlocked = {
                        if (autofillMode) {
                            finishWithFillResponse()
                        } else {
                            finish()
                        }
                    },
                )
            }
        }
    }

    private fun finishWithFillResponse() {
        // 重建响应要解密库内条目，放到协程里做，别卡住主线程
        lifecycleScope.launch {
            val response = runCatching {
                ZpasswdAutofillService.buildResponseAfterUnlock(this@UnlockActivity)
            }.getOrNull()
            if (response != null) {
                val data = Intent().apply {
                    putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
                }
                setResult(Activity.RESULT_OK, data)
            } else {
                setResult(Activity.RESULT_CANCELED)
            }
            finish()
        }
    }
}
