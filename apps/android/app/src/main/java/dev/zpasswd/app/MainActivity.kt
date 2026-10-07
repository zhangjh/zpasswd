package dev.zpasswd.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.fragment.app.FragmentActivity
import dev.zpasswd.app.data.VaultRepository
import dev.zpasswd.app.ui.ItemDetailScreen
import dev.zpasswd.app.ui.ItemEditScreen
import dev.zpasswd.app.ui.SettingsScreen
import dev.zpasswd.app.ui.UnlockScreen
import dev.zpasswd.app.ui.VaultListScreen
import kotlinx.coroutines.launch

/**
 * 主入口。FragmentActivity（指纹 BiometricPrompt 需要）。
 * 简单手写导航：unlock → list → detail/edit/settings。
 */
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Android 13+：保存凭证提醒通知需要运行时权限，一次性申请。
        // 用 framework 原生 requestPermissions（API 23+），不依赖 androidx.activity.result。
        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1001)
        }
        val repo = (application as ZpasswdApp).repo
        setContent {
            MaterialTheme {
                AppNav(activity = this, repo = repo)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        // 切后台即开始空闲计时（具体分钟数在设置里，默认 5）
        IdleLock.onBackground()
    }

    override fun onResume() {
        super.onResume()
        IdleLock.onForeground((application as ZpasswdApp).repo)
    }
}

sealed interface Route {
    data object Unlock : Route
    data object List : Route
    data class Detail(val id: String) : Route
    data class Edit(val id: String?) : Route
    data object Settings : Route
}

@Composable
fun AppNav(activity: FragmentActivity, repo: VaultRepository) {
    var route by remember { mutableStateOf<Route>(Route.Unlock) }
    val scope = rememberCoroutineScope()

    // 解锁态变化 → 自动跳登录/列表
    val unlocked by repo.unlocked.collectAsState()
    LaunchedEffect(unlocked) {
        route = if (unlocked) {
            if (route is Route.Unlock) Route.List else route
        } else {
            Route.Unlock
        }
    }

    // 待保存凭证提醒（Autofill onSaveRequest 收集的，每次回到前台刷新）
    var resumeTick by remember { mutableStateOf(0) }
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val obs = androidx.lifecycle.LifecycleEventObserver { _, e ->
            if (e == androidx.lifecycle.Lifecycle.Event.ON_RESUME) resumeTick++
        }
        lifecycleOwner.lifecycle.addObserver(obs)
        onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
    }
    val pendingSave = remember(resumeTick) {
        dev.zpasswd.app.autofill.PendingSave.peek()
    }

    when (val r = route) {
        is Route.Unlock -> UnlockScreen(
            activity = activity,
            repo = repo,
            onUnlocked = { route = Route.List },
        )
        is Route.List -> VaultListScreen(
            repo = repo,
            pendingSave = pendingSave,
            onItemClick = { route = Route.Detail(it) },
            onAdd = { route = Route.Edit(null) },
            onSettings = { route = Route.Settings },
            onPendingSaveConsumed = {
                // 消费掉队首，避免下次回到前台重复弹出
                dev.zpasswd.app.autofill.PendingSave.poll()
                resumeTick++
            },
        )
        is Route.Detail -> ItemDetailScreen(
            repo = repo,
            itemId = r.id,
            onEdit = { route = Route.Edit(r.id) },
            onBack = { route = Route.List },
        )
        is Route.Edit -> ItemEditScreen(
            repo = repo,
            itemId = r.id,
            onDone = { route = Route.List },
            onBack = { route = Route.List },
        )
        is Route.Settings -> SettingsScreen(
            activity = activity,
            repo = repo,
            onBack = { route = Route.List },
            onWipeAll = { scope.launch { route = Route.Unlock } },
        )
    }
}
