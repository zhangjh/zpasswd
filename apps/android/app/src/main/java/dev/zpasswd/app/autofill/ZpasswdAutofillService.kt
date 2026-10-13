package dev.zpasswd.app.autofill

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import dev.zpasswd.app.MainActivity
import dev.zpasswd.app.R
import dev.zpasswd.app.biometric.DeviceAutoUnlock
import dev.zpasswd.app.data.ItemWithPlain
import dev.zpasswd.app.data.VaultRepository
import dev.zpasswd.app.ui.UnlockActivity
import kotlinx.coroutines.*

/**
 * zpasswd 自动填充服务。
 *
 * 流程：
 * - onFillRequest 解析表单 → 非登录表单直接返回 null（不打扰）；vault 锁定则返回认证 Intent（跳解锁页）
 * - 解锁后按 eTLD+1（网页）/ 包名 + 应用名（原生 App）匹配条目，用系统下拉 dataset 展示
 * - onSaveRequest 收到新凭证 → 记为待保存，由 App 内展示确认
 *
 * 关于 inline suggestions：这里刻意**不启用**（见 res/xml/autofill_service_config.xml）。
 * IME 支持内嵌建议时，系统会把建议渲染到输入法建议栏而不是系统菜单里；一旦
 * InlinePresentation 的 Slice 格式不被系统接受，用户就完全看不到任何填充入口。
 * 系统下拉 dataset 是各 Android 版本 / 各输入法都必定生效的路径，优先保证可用。
 */
class ZpasswdAutofillService : AutofillService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var repo: VaultRepository

    override fun onCreate() {
        super.onCreate()
        AutofillDiag.log("服务 onCreate：进程已启动")
        repo = VaultRepository.get(this)
    }

    override fun onDestroy() {
        AutofillDiag.log("服务 onDestroy")
        super.onDestroy()
        scope.cancel()
    }

    // (onBind 在 AutofillService 中为 final，不可重写；onCreate 日志已足够判断系统是否拉起服务)

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val contexts = request.fillContexts
        val structure = contexts.lastOrNull()?.structure ?: run {
            AutofillDiag.log("onFillRequest: 无 structure")
            callback.onFailure("no structure"); return
        }
        val pkg = structure.activityComponent?.packageName ?: "?"
        AutofillDiag.log("onFillRequest: pkg=$pkg windows=${structure.windowNodeCount}")
        val form = StructureParser.parse(structure) ?: run {
            AutofillDiag.log("parse: 非登录表单，不介入")
            callback.onSuccess(null); return // 搜索框/评论框等，不打扰用户
        }
        AutofillDiag.log(
            "parse: webDomain=${form.webDomain} user=${form.usernameId != null} " +
                "pass=${form.passwordId != null} fillable=${form.fillableIds.size}",
        )

        scope.launch {
            try {
                if (!repo.isUnlocked()) {
                    // 设备免解锁：先试一次自动解包 DEK（Keystore 解密，几十毫秒），
                    // 成功就静默继续填充，不打扰用户去解锁。
                    val auto = runCatching { DeviceAutoUnlock.tryUnlock(repo) }.getOrDefault(false)
                    if (!auto) {
                        AutofillDiag.log("vault 锁定且免解锁不可用 → 返回解锁认证")
                        // 锁定：表单暂存进程内，返回认证 Intent 跳解锁页；解锁页直接重建响应
                        PendingAuth.form = form
                        val response = buildUnlockResponse(this@ZpasswdAutofillService, form)
                        withContext(Dispatchers.Main) { callback.onSuccess(response) }
                        return@launch
                    }
                    AutofillDiag.log("vault 锁定 → 设备免解锁成功，直接填充")
                }
                val matches = findMatches(this@ZpasswdAutofillService, repo, form)
                AutofillDiag.log("匹配条目: ${matches.size} 个 (库内共 ${repo.items.value.size} 条)")
                val response = buildFillResponse(this@ZpasswdAutofillService, form, matches)
                withContext(Dispatchers.Main) { callback.onSuccess(response) }
                AutofillDiag.log("已返回 FillResponse")
            } catch (e: Exception) {
                AutofillDiag.log("异常: ${e.message}")
                withContext(Dispatchers.Main) { callback.onFailure(e.message) }
            }
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val contexts = request.fillContexts
        val structure = contexts.lastOrNull()?.structure ?: run {
            AutofillDiag.log("onSaveRequest: 无 structure")
            callback.onFailure("no structure"); return
        }
        val form = StructureParser.parse(structure) ?: run {
            AutofillDiag.log("onSaveRequest: 未解析到表单")
            callback.onSuccess(); return
        }
        val username = form.usernameId?.let { form.currentValues[it] } ?: ""
        val password = form.passwordId?.let { form.currentValues[it] } ?: ""
        AutofillDiag.log(
            "onSaveRequest: domain=${form.webDomain} user=${username.isNotBlank()} " +
                "pass=${password.isNotBlank()}",
        )
        if (username.isBlank() && password.isBlank()) {
            callback.onSuccess(); return
        }
        scope.launch {
            // 记为待保存：先入队，再发通知把用户拉回 App 确认（避免后台静默写 vault）
            val pending = PendingCredential(
                packageName = form.packageName,
                webDomain = form.webDomain,
                username = username,
                password = password,
            )
            PendingSave.offer(pending)
            postSaveNotification(pending)
            withContext(Dispatchers.Main) { callback.onSuccess() }
        }
    }

    /** 发一条"保存新登录凭证"通知，点通知回到 App 确认入库。失败不影响主流程（横幅兜底仍在）。 */
    private fun postSaveNotification(pending: PendingCredential) {
        try {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        SAVE_CHANNEL_ID,
                        "保存凭证提醒",
                        NotificationManager.IMPORTANCE_DEFAULT,
                    ),
                )
            }
            val label = pending.webDomain ?: pending.packageName
            val openApp = PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java).apply {
                    action = "dev.zpasswd.app.ACTION_PENDING_SAVE"
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val notification = Notification.Builder(this, SAVE_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle("保存新登录凭证？")
                .setContentText(
                    "检测到 ${label}${if (pending.username.isNotBlank()) "（${pending.username}）" else ""} 的新登录，点击保存到保险库",
                )
                .setContentIntent(openApp)
                .setAutoCancel(true)
                .build()
            nm.notify(SAVE_NOTIFICATION_ID, notification)
        } catch (_: Exception) {
        }
    }

    companion object {
        private const val SAVE_CHANNEL_ID = "zpasswd_save"
        private const val SAVE_NOTIFICATION_ID = 1001

        /** 无匹配条目时，点"打开 zpasswd"回到 App 新建（带目标网址 / 包名） */
        const val ACTION_AUTOFILL_NEW = "dev.zpasswd.app.ACTION_AUTOFILL_NEW"
        const val EXTRA_AUTOFILL_TARGET = "autofill_target"

        /**
         * 解锁后由 UnlockActivity 调用，重建填充响应。
         *
         * 做成 companion（而非实例方法）是必要的：AutofillService 实例可能在用户解锁期间
         * 被系统回收，之前依赖 `UnlockActivity.service` 静态引用会导致解锁后拿不到响应、
         * 填充静默失败（只看到解锁页一闪而过）。
         */
        suspend fun buildResponseAfterUnlock(context: Context): FillResponse? {
            val form = PendingAuth.form ?: return null
            val repo = VaultRepository.get(context)
            val matches = findMatches(context, repo, form)
            val response = buildFillResponse(context, form, matches)
            PendingAuth.clear()
            return response
        }

        /** 进程内暂存：待认证的表单（解锁后继续填充）。 */
        object PendingAuth {
            var form: ParsedForm? = null
            fun clear() { form = null }
        }
    }
}

// ---------- 响应构建（顶层函数：service 实例与解锁页都能调用） ----------

/** 锁定态响应：点击后跳到解锁页，解锁完成由 UnlockActivity 回传真正的 FillResponse。 */
private fun buildUnlockResponse(context: Context, form: ParsedForm): FillResponse {
    val ids = listOfNotNull(form.usernameId, form.passwordId)
        .ifEmpty { form.fillableIds }
        .toTypedArray()
    val builder = FillResponse.Builder()
    if (ids.isEmpty()) return builder.build()
    val authIntent = Intent(context, UnlockActivity::class.java).apply {
        putExtra(UnlockActivity.EXTRA_AUTOFILL_MODE, true)
    }
    val sender = PendingIntent.getActivity(
        context,
        0,
        authIntent,
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
    ).intentSender
    @Suppress("DEPRECATION")
    builder.setAuthentication(ids, sender, remotePresentation(context, "解锁 zpasswd 以填充"))
    return builder.build()
}

/**
 * 匹配凭证：
 * - 显式 `androidapp://<包名>` 或 URL 恰好等于包名：直接命中
 * - WebView 场景（webDomain 非空）：按 eTLD+1 匹配
 * - 原生 App 场景（无 webDomain）：除上面两种外，再用「包名尾段 / 应用名」与条目的
 *   名称、URL host 做归一化比对 —— 否则网页 URL 存下来的条目永远匹配不到原生 App，
 *   表现就是"登录框完全不弹"。
 */
private suspend fun findMatches(
    context: Context,
    repo: VaultRepository,
    form: ParsedForm,
): List<ItemWithPlain> {
    // 确保内存列表最新
    if (repo.items.value.isEmpty()) repo.refreshItems()
    val all = repo.items.value
    if (all.isEmpty()) return emptyList()
    val domain = form.webDomain?.let { etldPlusOne(it) }
    val pkg = form.packageName
    val appTokens = if (domain == null) appTokensOf(context, pkg) else emptySet()
    AutofillDiag.log(
        "匹配依据: domain=${domain ?: "-"} pkg=$pkg " +
            "appTokens=[${appTokens.joinToString(",")}]",
    )
    return all.filter { item ->
        val url = item.plain.url.trim()
        if (url.isEmpty()) return@filter false
        when {
            // androidapp://com.example 显式绑定
            url.startsWith("androidapp://") ->
                url.removePrefix("androidapp://").substringBefore('/') == pkg
            // 包名直接匹配（用户在 URL 栏填了包名）
            url == pkg -> true
            // 网页：eTLD+1 匹配
            domain != null -> try {
                val host = url.substringAfter("://", url).substringBefore('/').substringBefore(':')
                etldPlusOne(host) == domain
            } catch (_: Exception) {
                false
            }
            // 原生 App：按应用身份模糊匹配
            else -> matchesAppIdentity(item, appTokens)
        }
    }.sortedByDescending { it.entity.favorite }
}

private fun buildFillResponse(
    context: Context,
    form: ParsedForm,
    matches: List<ItemWithPlain>,
): FillResponse {
    val builder = FillResponse.Builder()

    // 必须设置 SaveInfo，系统才会在登录后回调 onSaveRequest；不设则永不保存。
    val saveIds = listOfNotNull(form.usernameId, form.passwordId)
        .ifEmpty { form.fillableIds }
    if (saveIds.isNotEmpty()) {
        builder.setSaveInfo(
            SaveInfo.Builder(
                SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                saveIds.toTypedArray(),
            ).build(),
        )
    }

    var added = 0
    for (m in matches.take(5)) {
        // buildDataset 在没有任何可写字段时返回 null：空 Dataset 会让 build() 抛异常，
        // 一旦抛出整条 FillResponse 就变成 onFailure，系统连面板都不会弹。
        buildDataset(context, form, m)?.let {
            builder.addDataset(it)
            added++
        }
    }
    // 无匹配条目：补一个"打开 zpasswd 生成 / 保存"入口。
    // 否则 FillResponse 里既没有 dataset 也没有 authentication，系统不会弹任何东西。
    if (added == 0) addOpenAppEntry(context, builder, form)
    return builder.build()
}

/**
 * 兜底入口：把"打开 zpasswd"作为一个 authentication 项塞进 FillResponse。
 * 这样即使没有任何匹配凭证，登录框聚焦时系统也一定弹出面板，
 * 用户点一下即可回到 App 生成强密码 / 新建条目。
 */
private fun addOpenAppEntry(context: Context, builder: FillResponse.Builder, form: ParsedForm) {
    val ids = listOfNotNull(form.usernameId, form.passwordId)
        .ifEmpty { form.fillableIds }
        .toTypedArray()
    if (ids.isEmpty()) return
    try {
        val target = form.webDomain?.let { "https://$it" } ?: "androidapp://${form.packageName}"
        val intent = Intent(context, MainActivity::class.java).apply {
            action = ZpasswdAutofillService.ACTION_AUTOFILL_NEW
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(ZpasswdAutofillService.EXTRA_AUTOFILL_TARGET, target)
        }
        val sender = PendingIntent.getActivity(
            context,
            1,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        ).intentSender
        @Suppress("DEPRECATION")
        builder.setAuthentication(ids, sender, remotePresentation(context, "打开 zpasswd 生成 / 保存"))
    } catch (_: Exception) {
        // 兜底失败不影响主流程
    }
}

private fun buildDataset(context: Context, form: ParsedForm, item: ItemWithPlain): Dataset? {
    // 没有用户名/密码字段可写时直接放弃这条 dataset（空 dataset 无法 build）。
    if (form.usernameId == null && form.passwordId == null) return null
    val label = item.plain.name.ifBlank { item.plain.username }
    val builder = Dataset.Builder(remotePresentation(context, label))
    form.usernameId?.let { builder.setValue(it, AutofillValue.forText(item.plain.username)) }
    form.passwordId?.let { builder.setValue(it, AutofillValue.forText(item.plain.password)) }
    return try {
        builder.build()
    } catch (_: Exception) {
        null // 空 dataset / 字段无效：跳过这一条而不是让整个请求失败
    }
}

private fun remotePresentation(context: Context, text: String): RemoteViews {
    // RemoteViews 必须用本包资源：之前用 android.R.layout.simple_list_item_1
    // 配本包名，系统 inflate 失败会静默丢弃整个 dataset。
    val rv = RemoteViews(context.packageName, R.layout.zp_autofill_item)
    rv.setTextViewText(R.id.zp_text, text)
    return rv
}

// ---------- 原生 App 身份匹配 ----------

/** 应用名 + 包名尾段归一化成 token 集合（如 com.tencent.mm / "微信"）。 */
private fun appTokensOf(context: Context, pkg: String): Set<String> {
    if (pkg.isBlank()) return emptySet()
    val tokens = mutableSetOf<String>()
    pkg.substringAfterLast('.').let { if (it.length >= 3) tokens += normalizeToken(it) }
    appLabelOf(context, pkg)?.let { label ->
        val whole = normalizeToken(label)
        if (whole.length >= 3) tokens += whole
        label.split(Regex("[^\\p{L}\\p{N}]+")).forEach { w ->
            val n = normalizeToken(w)
            if (n.length >= 4) tokens += n
        }
    }
    return tokens
}

private fun matchesAppIdentity(item: ItemWithPlain, appTokens: Set<String>): Boolean {
    if (appTokens.isEmpty()) return false
    val host = try {
        if (item.plain.url.contains("://")) java.net.URI(item.plain.url).host?.lowercase()
        else item.plain.url.substringBefore('/').lowercase()
    } catch (_: Exception) {
        null
    }
    val candidates = mutableSetOf<String>()
    candidates += normalizeToken(item.plain.name)
    host?.let {
        candidates += normalizeToken(it)                      // github.com → githubcom
        candidates += normalizeToken(it.substringBefore('.')) // github
    }
    candidates.removeAll { it.length < 3 }
    return candidates.any { c ->
        appTokens.any { a ->
            c == a || (c.length >= 4 && a.length >= 4 && (c.contains(a) || a.contains(c)))
        }
    }
}

private fun normalizeToken(s: String): String = s.lowercase().filter { it.isLetterOrDigit() }

private fun appLabelOf(context: Context, pkg: String): String? = try {
    val pm = context.packageManager
    val info = if (Build.VERSION.SDK_INT >= 33) {
        pm.getApplicationInfo(pkg, PackageManager.ApplicationInfoFlags.of(0))
    } else {
        @Suppress("DEPRECATION")
        pm.getApplicationInfo(pkg, 0)
    }
    pm.getApplicationLabel(info).toString()
} catch (_: Exception) {
    null // 包不可见 / 已卸载
}

data class PendingCredential(
    val packageName: String,
    val webDomain: String?,
    val username: String,
    val password: String,
)

/** 待保存凭证队列（App 前台消费）。 */
object PendingSave {
    private val queue = ArrayDeque<PendingCredential>()
    fun offer(c: PendingCredential) { synchronized(queue) { queue.addLast(c) } }
    fun poll(): PendingCredential? = synchronized(queue) { queue.removeFirstOrNull() }
    fun peek(): PendingCredential? = synchronized(queue) { queue.firstOrNull() }
}
