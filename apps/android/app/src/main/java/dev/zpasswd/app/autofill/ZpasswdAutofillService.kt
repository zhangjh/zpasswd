package dev.zpasswd.app.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
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
        dev.zpasswd.app.ui.UnlockActivity.ServiceRef.service = this
    }

    override fun onDestroy() {
        super.onDestroy()
        if (dev.zpasswd.app.ui.UnlockActivity.ServiceRef.service === this) {
            dev.zpasswd.app.ui.UnlockActivity.ServiceRef.service = null
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
            callback.onFailure("no structure"); return
        }
        val form = StructureParser.parse(structure) ?: run {
            callback.onSuccess(null); return // 没有可填的框，不打扰用户
        }

        scope.launch {
            try {
                if (!repo.isUnlocked()) {
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
                val response = buildFillResponse(request, form, matches)
                withContext(Dispatchers.Main) { callback.onSuccess(response) }
            } catch (e: Exception) {
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
            setInlinePresentation(builder, inlineSpec as android.view.inputmethod.InlinePresentationSpec, form, item, label)
        }
        return builder.build()
    }

    @RequiresApi(30)
    private fun setInlinePresentation(
        builder: Dataset.Builder,
        spec: android.view.inputmethod.InlinePresentationSpec,
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
            val inlinePresentation = android.view.inputmethod.InlinePresentation(
                slice, spec, null, false,
            )
            form.usernameId?.let {
                builder.setValue(
                    it, AutofillValue.forText(item.plain.username), inlinePresentation,
                )
            }
        } catch (_: Exception) {
            // inline 失败则静默降级为下拉（dataset 已有 RemoteViews）
        }
    }

    private fun remotePresentation(text: String): RemoteViews {
        val rv = RemoteViews(packageName, android.R.layout.simple_list_item_1)
        rv.setTextViewText(android.R.id.text1, text)
        return rv
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val contexts = request.fillContexts
        val structure = contexts.lastOrNull()?.structure ?: run {
            callback.onFailure("no structure"); return
        }
        val form = StructureParser.parse(structure) ?: run {
            callback.onSuccess(); return
        }
        val username = form.usernameId?.let { form.currentValues[it] } ?: ""
        val password = form.passwordId?.let { form.currentValues[it] } ?: ""
        if (username.isBlank() && password.isBlank()) {
            callback.onSuccess(); return
        }
        scope.launch {
            // 记为待保存，由 App 内展示确认（避免后台静默写 vault）
            PendingSave.offer(
                PendingCredential(
                    packageName = form.packageName,
                    webDomain = form.webDomain,
                    username = username,
                    password = password,
                ),
            )
            withContext(Dispatchers.Main) { callback.onSuccess() }
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

/** 待保存凭证队列（App 前台消费）。 */
object PendingSave {
    private val queue = ArrayDeque<PendingCredential>()
    fun offer(c: PendingCredential) { synchronized(queue) { queue.addLast(c) } }
    fun poll(): PendingCredential? = synchronized(queue) { queue.removeFirstOrNull() }
    fun peek(): PendingCredential? = synchronized(queue) { queue.firstOrNull() }
}
