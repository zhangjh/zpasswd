package dev.zpasswd.app.ui

import android.app.Activity
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.fragment.app.FragmentActivity
import dev.zpasswd.app.ZpasswdApp
import dev.zpasswd.app.autofill.ZpasswdAutofillService
import dev.zpasswd.app.data.VaultRepository

/**
 * 解锁页。两种模式：
 * - 普通：App 内解锁，成功后 finish（MainActivity 会自己跳转）。
 * - Autofill 认证（EXTRA_AUTOFILL_MODE=true）：由 AutofillService 的 PendingIntent 拉起，
 *   解锁成功后把 FillResponse 塞进 EXTRA_AUTHENTICATION_RESULT 返回给系统。
 */
class UnlockActivity : FragmentActivity() {
    companion object {
        const val EXTRA_AUTOFILL_MODE = "autofill_mode"

        /** 进程内 service 引用（service onCreate 时注册）。 */
        @Volatile
        var service: ZpasswdAutofillService? = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val repo = (application as ZpasswdApp).repo
        val autofillMode = intent.getBooleanExtra(EXTRA_AUTOFILL_MODE, false)
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
        // 从 service 取到已缓存的表单，重建填充响应
        val service = lastServiceRef()
        val response = service?.buildAuthenticatedResponse()
        if (response != null) {
            val data = android.content.Intent().apply {
                putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response)
            }
            setResult(Activity.RESULT_OK, data)
        } else {
            setResult(Activity.RESULT_CANCELED)
        }
        finish()
    }

    private fun lastServiceRef(): ZpasswdAutofillService? = service
}
