package dev.zpasswd.app.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
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
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import dev.zpasswd.app.MainActivity
import dev.zpasswd.app.R
import dev.zpasswd.app.data.ItemWithPlain
import dev.zpasswd.app.data.VaultRepository
import kotlinx.coroutines.*

/**
 * zpasswd 自动填充服务。
 *
 * 流程：
 * - onFillRequest 解析表单 → vault 锁定则返回认证 Intent（跳解锁页）
 * - 解锁后按 eTLD+1（网页）/包名（App）匹配条目，API 30+ 用 inline suggestions，低版本用下拉 dataset
 * - onSaveRequest 收到新凭证 → 记为待保存，由 App 内展示确认
 */
class ZpasswdAutofillService : AutofillService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var repo: VaultRepository

    override fun onCreate() {
        super.onCreate()
        repo = VaultRepository.get(this)
        dev.zpasswd.app.ui.UnlockActivity.service = this
    }

    override fun onDestroy() {
        super.onDestroy()
        if (dev.zpasswd.app.ui.UnlockActivity.service === this) {
            dev.zpasswd.app.ui.UnlockActivity.service = null
        }
        scope.cancel()
    }

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
            AutofillDiag.log("parse: 未找到可填字段")
            callback.onSuccess(null); return // 没有可填的框，不打扰用户
        }
        AutofillDiag.log(
            "parse: webDomain=${form.webDomain} user=${form.usernameId != null} " +
                "pass=${form.passwordId != null} fillable=${form.fillableIds.size}",
        )

        scope.launch {
            try {
                if (!repo.isUnlocked()) {
                    AutofillDiag.log("vault 锁定 → 返回解锁认证")
                    // 锁定：返回认证流程，解锁后继续
                    PendingAuth.form = form
                    PendingAuth.clientState = request.clientState
                    val authIntent = Intent(this@ZpasswdAutofillService, dev.zpasswd.app.ui.UnlockActivity::class.java).apply {
                        putExtra(dev.zpasswd.app.ui.UnlockActivity.EXTRA_AUTOFILL_MODE, true)
                    }
                    val sender = PendingIntent.getActivity(
                        this@ZpasswdAutofillService, 0, authIntent,
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
                    ).intentSender
                    val ids = listOfNotNull(form.usernameId, form.passwordId)
                        .ifEmpty { form.fillableIds }.toTypedArray()
                    val presentation = remotePresentation("解锁 zpasswd 以填充")
                    val response = FillResponse.Builder()
                        .setAuthentication(ids, sender, presentation)
                        .build()
                    withContext(Dispatchers.Main) { callback.onSuccess(response) }
                    return@launch
                }
                val matches = findMatches(form)
                AutofillDiag.log("匹配条目: ${matches.size} 个 (库内共 ${repo.items.value.size} 条)")
                val response = buildFillResponse(request, form, matches)
                withContext(Dispatchers.Main) { callback.onSuccess(response) }
                AutofillDiag.log("已返回 FillResponse")
            } catch (e: Exception) {
                AutofillDiag.log("异常: ${e.message}")
                withContext(Dispatchers.Main) { callback.onFailure(e.message) }
            }
        }
    }

    /** 解锁后（经 UnlockActivityBridge 回调）继续构建真正的填充响应。 */
    fun buildAuthenticatedResponse(): FillResponse? {
        val form = PendingAuth.form ?: return null
        val matches = runBlocking { findMatches(form) }
        // request 已不可用，用简化版 response（无 inline）
        val builder = FillResponse.Builder()
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
        for (m in matches) {
            builder.addDataset(buildDataset(form, m, inlineSpec = null))
        }
        PendingAuth.clear()
        return builder.build()
    }

    private suspend fun findMatches(form: ParsedForm): List<ItemWithPlain> {
        // 确保内存列表最新
        if (repo.items.value.isEmpty()) repo.refreshItems()
        val all = repo.items.value
        if (all.isEmpty()) return emptyList()
        val domain = form.webDomain?.let { etldPlusOne(it) }
        val pkg = form.packageName
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
                } catch (_: Exception) { false }
                else -> false
            }
        }.sortedByDescending { it.entity.favorite }
    }

    private fun buildFillResponse(
        request: FillRequest,
        form: ParsedForm,
        matches: List<ItemWithPlain>,
    ): FillResponse {
        val builder = FillResponse.Builder()
        val inlineSpec = if (Build.VERSION.SDK_INT >= 30) {
            request.inlineSuggestionsRequest?.inlinePresentationSpecs?.firstOrNull()
        } else null

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

        if (matches.isEmpty()) {
            // 无匹配：仍提供一个 dataset 打开 App（方便新建），或直接返回空
            return builder.build()
        }
        for (m in matches.take(5)) {
            builder.addDataset(buildDataset(form, m, inlineSpec))
        }
        return builder.build()
    }

    private fun buildDataset(
        form: ParsedForm,
        item: ItemWithPlain,
        inlineSpec: Any?,
    ): Dataset {
        val label = item.plain.name.ifBlank { item.plain.username }
        val builder = Dataset.Builder(remotePresentation(label))
        form.usernameId?.let { builder.setValue(it, AutofillValue.forText(item.plain.username)) }
        form.passwordId?.let { builder.setValue(it, AutofillValue.forText(item.plain.password)) }
        if (Build.VERSION.SDK_INT >= 30 && inlineSpec != null) {
            setInlinePresentation(builder, inlineSpec as android.widget.inline.InlinePresentationSpec, form, item, label)
        }
        return builder.build()
    }

    @RequiresApi(30)
    private fun setInlinePresentation(
        builder: Dataset.Builder,
        spec: android.widget.inline.InlinePresentationSpec,
        form: ParsedForm,
        item: ItemWithPlain,
        label: String,
    ) {
        try {
            // 纯 framework 实现 inline suggestion（API 30+）：
            // Slice 走 "androidx.slice" spec，InlinePresentation 挂到 dataset 上。
            // 格式不对系统会直接忽略 → 静默降级为下拉 dataset。
            val sliceUri = android.net.Uri.parse("content://dev.zpasswd.app/inline/${item.entity.id}")
            val slice = android.app.slice.Slice.Builder(
                sliceUri,
                android.app.slice.SliceSpec("androidx.slice", 1),
            ).apply {
                addText(label, null, listOf("title"))
                if (item.plain.username.isNotBlank()) {
                    addText(item.plain.username, null, listOf("subtitle"))
                }
            }.build()
            val inlinePresentation = android.service.autofill.InlinePresentation(
                slice, spec, false,
            )
            form.usernameId?.let {
                builder.setValue(
                    it,
                    AutofillValue.forText(item.plain.username),
                    remotePresentation(label),
                    inlinePresentation,
                )
            }
        } catch (_: Exception) {
            // inline 失败则静默降级为下拉（dataset 已有 RemoteViews）
        }
    }

    private fun remotePresentation(text: String): RemoteViews {
        // RemoteViews 必须用本包资源：之前用 android.R.layout.simple_list_item_1
        // 配本包名，系统 inflate 失败会静默丢弃整个 dataset。
        val rv = RemoteViews(packageName, R.layout.zp_autofill_item)
        rv.setTextViewText(R.id.zp_text, text)
        return rv
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

    companion object {
        private const val SAVE_CHANNEL_ID = "zpasswd_save"
        private const val SAVE_NOTIFICATION_ID = 1001
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

    /** 进程内暂存：待认证的表单（解锁后继续填充）。 */
    object PendingAuth {
        var form: ParsedForm? = null
        var clientState: android.os.Bundle? = null
        fun clear() { form = null; clientState = null }
    }
}

data class PendingCredential(
    val packageName: String,
    val webDomain: String?,
    val username: String,
    val password: String,
)

/** 自动填充诊断日志：记录最近 50 条服务侧事件，供设置页"自动填充诊断"展示。 */
object AutofillDiag {
    data class Event(val time: String, val msg: String)

    private val events = ArrayDeque<Event>()

    fun log(msg: String) {
        val t = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
            .format(java.util.Date())
        synchronized(events) {
            events.addLast(Event(t, msg))
            while (events.size > 50) events.removeFirst()
        }
    }

    fun snapshot(): List<Event> = synchronized(events) { events.toList().asReversed() }

    fun clear() = synchronized(events) { events.clear() }
}

/** 待保存凭证队列（App 前台消费）。 */
object PendingSave {
    private val queue = ArrayDeque<PendingCredential>()
    fun offer(c: PendingCredential) { synchronized(queue) { queue.addLast(c) } }
    fun poll(): PendingCredential? = synchronized(queue) { queue.removeFirstOrNull() }
    fun peek(): PendingCredential? = synchronized(queue) { queue.firstOrNull() }
}
