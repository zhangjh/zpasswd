package dev.zpasswd.app.autofill

import android.accessibilityservice.AccessibilityService
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import android.graphics.PixelFormat
import android.graphics.Rect
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.LinearLayout
import android.widget.TextView
import dev.zpasswd.app.MainActivity
import dev.zpasswd.app.biometric.DeviceAutoUnlock
import dev.zpasswd.app.data.ItemWithPlain
import dev.zpasswd.app.data.VaultRepository
import dev.zpasswd.app.ui.UnlockActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlin.math.min

/**
 * 浏览器自动填充（无障碍服务）。
 *
 * ## 为什么必须有这个服务
 *
 * Android 官方自动填充框架（[ZpasswdAutofillService]）依赖目标 App 把输入框通过
 * `AssistStructure` 交出来。真机实测（Android 16 / HyperOS / Edge 153）：
 *
 * - `com.microsoft.emmx`（Edge）在 HTTPS 登录页上**连一个 FillRequest 都不发**；
 * - `com.android.browser`（小米浏览器）**只交出地址栏**，页面里的密码框不在
 *   `AssistStructure` 里（框架日志 `AutofillableIds` 只有一个 id）。
 *
 * 这是 Chromium 内核的既定行为：网页密码框不会走第三方自动填充服务。
 * 所以 Bitwarden / 1Password / Dashlane 全都额外做一套无障碍服务。
 *
 * ## 实测到的无障碍节点树（Edge + news.ycombinator.com/login）
 *
 * ```
 * android.webkit.WebView
 *   android.widget.EditText  password=false   ← 登录表单·用户名
 *   android.widget.EditText  password=true    ← 登录表单·密码
 *   android.widget.EditText  password=false   ← 注册表单·用户名
 *   android.widget.EditText  password=true    ← 注册表单·密码
 *   android.widget.EditText  id=...:id/url_bar  text=news.ycombinator.com
 * ```
 *
 * 也就是说：`isPassword` / `isFocused` / 地址栏 id 在网页节点上**都是可用的**，
 * 无障碍这条路能走通。本文件按这个结构实现识别与填充。
 *
 * ## 工作方式
 *
 * 1. 监听 `TYPE_VIEW_FOCUSED` / `TYPE_VIEW_CLICKED`，以及节流后的内容变化事件；
 * 2. 前序遍历节点树，收集可编辑框、地址栏、当前聚焦框；
 * 3. 命中登录场景时，用 `TYPE_ACCESSIBILITY_OVERLAY` 窗口在输入框下方弹小面板
 *    （该窗口类型不需要 `SYSTEM_ALERT_WINDOW` 权限）；
 * 4. 点候选项 → `ACTION_FOCUS` + `ACTION_SET_TEXT`，WebView 不接受时退回
 *    「剪贴板 + `ACTION_PASTE`」。
 *
 * ## 边界
 *
 * 只在「浏览器包名」或「节点树里确实有 WebView」时介入，避免和已经工作的官方
 * 自动填充服务（原生 App 场景）抢界面、弹两套。
 */
class ZpasswdAccessibilityService : AccessibilityService() {

    private lateinit var wm: WindowManager
    private val mainHandler = Handler(Looper.getMainLooper())
    private var panel: View? = null
    private var panelState: PanelState? = null

    /** 上一次弹面板的标识（包名 + 域名 + 字段指纹），用于去重，避免面板反复重建。 */
    private var lastKey: String? = null

    /** 上次弹出面板的时间，配合 lastKey 做去重窗口（防止 dismiss 后同字段事件立刻重建）。 */
    private var lastShownAt = 0L

    /** 内容变化事件很密集，做节流。 */
    private var lastContentEventAt = 0L

    /** 事件诊断日志的节流时间戳（见 onAccessibilityEvent 顶部）。 */
    private var lastEventLogAt = 0L

    /** 解锁回来后需要重试的场景（vault 锁定时点过「解锁」）。 */
    private var pendingRetry: PendingRetry? = null

    /** 设备免解锁只尝试一次，失败就老实弹"解锁"面板，避免无限重试。 */
    private var autoUnlockAttempted = false

    /** 免解锁 / 解密等 IO 用。每次服务连接重建，断开时取消。 */
    private var ioScope: CoroutineScope? = null

    /** 调试广播（仅 debuggable 包注册），用于在无法注入触摸事件的环境下验证填充链路。 */
    private var debugReceiver: BroadcastReceiver? = null

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
        wm = getSystemService(WINDOW_SERVICE) as WindowManager
        ioScope?.cancel()
        ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        autoUnlockAttempted = false
        AutofillDiag.log("无障碍服务已连接（浏览器自动填充可用）")
        registerDebugReceiverIfDebuggable()
        // 进程刚起来时 vault 是锁的；主动免解锁一次，用户点密码框就能直接看到条目
        ioScope?.launch {
            val ok = runCatching { DeviceAutoUnlock.tryUnlock(VaultRepository.get(this@ZpasswdAccessibilityService)) }
                .getOrDefault(false)
            if (ok) AutofillDiag.log("无障碍：启动时已通过设备免解锁进入解锁态")
        }
    }

    override fun onUnbind(intent: Intent?): Boolean {
        AutofillDiag.log("无障碍服务已断开")
        teardown()
        if (instance === this) instance = null
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        teardown()
        if (instance === this) instance = null
        super.onDestroy()
    }

    override fun onInterrupt() {
        // 系统会在无障碍焦点变化等时机调用；面板被它收掉会导致"闪烁"，
        // 所以这里记一条日志，便于区分是用户点了别处还是系统打断。
        dismissPanel("onInterrupt")
    }

    // ------------------------------------------------------------------
    // 事件入口
    // ------------------------------------------------------------------

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName) return // 自己的界面（含本服务弹出的面板）不处理

        // 诊断：确认"事件到底有没有来"。限流到最多 ~1 条/800ms，避免刷屏。
        // 排查"点了密码框却毫无反应"时，先看有没有这一行：
        // 没有 → 系统没把事件给我们；有但类型不对 → 是我们漏听了事件类型。
        val nowEvt = System.currentTimeMillis()
        if (nowEvt - lastEventLogAt > 800) {
            lastEventLogAt = nowEvt
            AutofillDiag.log(
                "无障碍事件: ${AccessibilityEvent.eventTypeToString(event.eventType)} pkg=$pkg",
            )
        }

        when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_FOCUSED,
            AccessibilityEvent.TYPE_VIEW_CLICKED,
            -> evaluate(pkg, event.source)

            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                // 网页是异步渲染的：密码框常常在事件之后才出现，这里做一次带节流的复查。
                val now = System.currentTimeMillis()
                if (now - lastContentEventAt < CONTENT_EVENT_THROTTLE_MS) return
                lastContentEventAt = now
                if (panel != null) return
                evaluate(pkg, null)
            }

            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                // 切窗口/切 App：收起面板（解锁页返回时由 pendingRetry 负责重新弹出）。
                // 系统瞬时窗口（小窗、负一屏、通知栏等）不算"离开登录场景"，
                // 否则它们一冒头面板就被收掉，肉眼看到的是闪一下。
                if (panelState != null && panelState?.pkg != pkg && pkg !in TRANSIENT_WINDOW_PKGS) {
                    dismissPanel("切换窗口→$pkg")
                }
                // 换了个 App 就等于"上一次填充尝试结束"：重置免解锁闩锁。
                // 否则一次失败（例如那一刻密文还没登记好）会让整个服务生命周期都要求解锁，
                // 用户看到的是"免解锁开关明明开着却没用"。
                if (pkg !in TRANSIENT_WINDOW_PKGS) autoUnlockAttempted = false
                retryIfPending(pkg)
            }
        }
    }

    // ------------------------------------------------------------------
    // 核心判定
    // ------------------------------------------------------------------

    /**
     * @param allowUnfocused 仅"解锁页返回浏览器"的重试路径为 true：那时 Chromium 不一定
     *   还保留焦点，但仍应把面板弹回来。普通事件路径一律要求**密码框获得焦点**才弹。
     */
    private fun evaluate(
        pkg: String,
        eventSource: AccessibilityNodeInfo?,
        allowUnfocused: Boolean = false,
    ) {
        if (!isAutofillEnabled(this)) return
        // 跨窗口遍历：输入法弹起后 rootInActiveWindow 常常只给到局部窗口，
        // 单看它会把 WebView 和账号框都看丢（见 analyzeAllWindows 注释）。
        // 拿不到任何窗口根时保持现状（不误判成"非登录框"把已有面板收掉）。
        val info = analyzeAllWindows(pkg) ?: return

        // 只在"网页场景"介入：浏览器包名，或节点树里确实存在 WebView。
        // 原生 App 的登录框交给官方自动填充服务，避免弹两套界面。
        val isBrowser = pkg in BROWSER_PACKAGES
        if (!isBrowser && !info.hasWebView) return

        // 聚焦字段：节点树里带 isFocused 的最可靠；事件源做兜底。
        // 兜底时只接受**真正的输入框**——页面加载/重绘时事件源常常是 WebView、FrameLayout
        // 这类容器，把它们当成"聚焦的输入框"会得出"聚焦的不是密码框"，白白把面板收掉。
        val f = info.focusedEditable
            ?: eventSource?.let { ev -> info.fields.firstOrNull { it == ev } }
            ?: eventSource?.takeIf { isInputNode(it) }

        // 只有"真实的聚焦/点击事件"才记这一行（eventSource 非空即表示来自 FOCUSED/CLICKED）。
        // 内容变化事件是高频的，跟着记会把诊断日志刷爆，也会把这里淹掉。
        // 这一行是排查"为什么没弹/弹错框"的关键：能直接看到焦点落在哪个框、是不是密码框。
        if (eventSource != null) {
            AutofillDiag.log(
                "无障碍焦点: pkg=$pkg f=${f?.let { describe(it) } ?: "-"} " +
                    "是密码=${f?.let { isPasswordField(it) }} webView=${info.hasWebView} " +
                    "字段数=${info.fields.size} 窗口数=${info.rootCount}",
            )
        }

        // 点的是地址栏 → 不是登录行为，收起面板不打扰
        if (f != null && isUrlBar(f, pkg)) {
            dismissPanel("聚焦地址栏")
            return
        }

        // 只有**密码框**获得焦点才弹面板。
        // 用户名 / 邮箱 / 手机号 / 搜索框都不是密码框，弹出来只会打扰用户；
        // 用户点账号框后通常紧接着点密码框，那时再弹即可。
        if (f != null && !isPasswordField(f)) {
            dismissPanel("非密码框")
            return
        }

        val domain = info.domain
        val passwordNode: AccessibilityNodeInfo? = when {
            f != null -> f
            // 无焦点兜底：只在"明确是网页且已解析出域名"时才取第一个密码框
            allowUnfocused && info.hasWebView && domain != null ->
                info.fields.firstOrNull { isPasswordField(it) }
            else -> null
        }
        if (passwordNode == null) {
            dismissPanel("非登录框")
            return
        }

        val usernameNode = resolveUsername(info.fields, passwordNode, info.urlBarNode, f)
        val anchor = Rect().also { passwordNode.getBoundsInScreen(it) }

        AutofillDiag.log(
            "无障碍: pkg=$pkg domain=${domain ?: "-"} webView=${info.hasWebView} " +
                "账号=${usernameNode?.let { describe(it) } ?: "-"} " +
                "密码=${describe(passwordNode)} 聚焦=${f?.let { describe(it) } ?: "-"}",
        )

        // 去重：同一字段在短时间内反复触发事件（Chromium 内容变化极密集）时不要重建面板。
        // 只判断 panel != null 不够——中间只要有一次 dismiss（如 onInterrupt），
        // 后面每个事件都会重新弹一次，肉眼看到的就是闪烁。
        val key = "$pkg|${domain ?: "-"}|${describe(passwordNode)}|${usernameNode != null}"
        val now = System.currentTimeMillis()
        if (key == lastKey && (panel != null || now - lastShownAt < PANEL_DEBOUNCE_MS)) return
        lastKey = key

        val repo = VaultRepository.get(this)
        if (repo.isUnlocked()) {
            // 已经解锁：清掉"免解锁只试一次"的闩锁。
            // 否则一旦在本轮解锁前失败过一次（例如用户还没解锁过、密文尚未登记），
            // 之后空闲自动锁定就再也不会尝试免解锁，用户每次都被要求解锁——正是要修掉的体验。
            autoUnlockAttempted = false
        } else {
            // 设备免解锁：先尝试用 Keystore 自动解包 DEK。成功就继续走填充，
            // 用户不需要为一次填充手动解锁（这是默认开启的行为）。
            if (!autoUnlockAttempted) {
                autoUnlockAttempted = true
                ioScope?.launch {
                    val ok = runCatching { DeviceAutoUnlock.tryUnlock(repo) }.getOrDefault(false)
                    if (ok) {
                        AutofillDiag.log("无障碍：设备免解锁成功，直接填充")
                    } else {
                        val enrolled = runCatching { DeviceAutoUnlock.isEnrolled(repo) }
                            .getOrDefault(false)
                        AutofillDiag.log(
                            if (enrolled) "无障碍：设备免解锁失败（密文解不开）→ 请求解锁"
                            else "无障碍：免解锁尚未登记（先解锁一次即可）→ 请求解锁",
                        )
                    }
                    mainHandler.post {
                        if (ok) {
                            // 解锁成功：清掉去重键，让面板带着真实条目重建
                            lastKey = null
                            lastShownAt = 0
                            evaluate(pkg, eventSource, allowUnfocused)
                        } else if (panel == null) {
                            // 失败：弹"解锁"面板。加 panel == null 是因为解密期间
                            // 往往还有事件走到下面那行 showUnlockPanel，两边都弹会重复 addView，
                            // 肉眼看到的就是面板闪一下。
                            showUnlockPanel(pkg, domain, usernameNode, passwordNode, anchor)
                        }
                    }
                }
                return
            }
            showUnlockPanel(pkg, domain, usernameNode, passwordNode, anchor)
            return
        }

        val matches = matchItems(repo, domain, pkg, info.hasWebView)
        AutofillDiag.log("无障碍匹配条目: ${matches.size} 个")
        val rows = if (matches.isEmpty()) {
            listOf(Row("在 zpasswd 中新建", RowAction.Create))
        } else {
            matches.take(MAX_ROWS).map { Row(labelOf(it), RowAction.Fill(it)) }
        }
        panelState = PanelState(pkg, domain, FieldSet(usernameNode, passwordNode), rows)
        showPanel(anchor)
    }

    /** vault 锁定且设备免解锁不可用时，弹"解锁 zpasswd 以填充"。 */
    private fun showUnlockPanel(
        pkg: String,
        domain: String?,
        username: AccessibilityNodeInfo?,
        password: AccessibilityNodeInfo,
        anchor: Rect,
    ) {
        panelState = PanelState(
            pkg = pkg,
            domain = domain,
            fields = FieldSet(username, password),
            rows = listOf(Row("解锁 zpasswd 以填充", RowAction.Unlock)),
        )
        showPanel(anchor)
    }

    /**
     * 选账号框。优先级：
     * 1. 聚焦框本身就是账号框（有 user/email/account 等语义）；
     * 2. 密码框在文档顺序里的前一个可编辑框（HN、GitHub 这类无 id 无 hint 的表单靠这条）；
     * 3. 树里第一个有账号语义的框；
     * 4. 树里唯一的非密码可编辑框。
     */
    private fun resolveUsername(
        fields: List<AccessibilityNodeInfo>,
        password: AccessibilityNodeInfo?,
        urlBar: AccessibilityNodeInfo?,
        focused: AccessibilityNodeInfo?,
    ): AccessibilityNodeInfo? {
        fun usable(n: AccessibilityNodeInfo) = n != urlBar && !isPasswordField(n)

        if (focused != null && usable(focused) && isUsernameField(focused)) return focused

        if (password != null) {
            val idx = fields.indexOfFirst { it == password }
            for (i in idx - 1 downTo 0) {
                if (usable(fields[i])) return fields[i]
            }
        }
        fields.firstOrNull { usable(it) && isUsernameField(it) }?.let { return it }
        return fields.filter { usable(it) }.singleOrNull()
    }

    // ------------------------------------------------------------------
    // 节点树分析
    // ------------------------------------------------------------------

    private class TreeInfo(
        val fields: List<AccessibilityNodeInfo>,
        val hasWebView: Boolean,
        val domain: String?,
        val urlBarNode: AccessibilityNodeInfo?,
        val focusedEditable: AccessibilityNodeInfo?,
        /** 实际合并了几个窗口根（诊断用：输入法弹起后这个数会 >1）。 */
        val rootCount: Int = 1,
    )

    private class FieldSet(
        val username: AccessibilityNodeInfo?,
        val password: AccessibilityNodeInfo?,
    )

    private class AnalyzeAcc {
        val fields = mutableListOf<AccessibilityNodeInfo>()
        var visited = 0
        var hasWebView = false
        var focusedEditable: AccessibilityNodeInfo? = null
        var bestPriority = 0
        var bestDomain: String? = null
        var urlBarNode: AccessibilityNodeInfo? = null
    }

    /** 前序遍历（保持文档顺序，"密码框前一个可编辑框"这条规则依赖它）。 */
    private fun analyze(root: AccessibilityNodeInfo, pkg: String): TreeInfo {
        val acc = AnalyzeAcc()
        walk(root, pkg, 0, acc)
        return TreeInfo(acc.fields, acc.hasWebView, acc.bestDomain, acc.urlBarNode, acc.focusedEditable)
    }

    /**
     * 合并所有交互窗口的节点树。
     *
     * 为什么需要：`rootInActiveWindow` 有时只给到**局部窗口**——实测小米浏览器在输入法
     * 弹起后，活动窗口的树里只剩密码框，WebView 与账号框都不见了
     * （日志 `webView=false 账号=- 密码=EditText#p`），结果只填了密码没填账号。
     * 填充是一次性动作，多遍历几个窗口的开销可以接受。
     *
     * **只合并属于 `pkg` 的窗口**。`windows` 里同时存在输入法、状态栏、以及后台浏览器的窗口，
     * 无差别合并会出大问题：只要后台开着一个浏览器，"是不是网页场景"的判断就会被那个
     * 后台 WebView 满足，于是**任何 App 的任何事件都能弹出浏览器里的填充面板**——
     * 实测点用户名框时输入法一弹起（事件 pkg=com.android.systemui），面板就又冒出来了。
     *
     * @return 连一个窗口根都拿不到时返回 null——调用方据此**保持现状**，
     *   而不是把"暂时读不到树"误判成"这里不是登录框"从而收掉已经弹出的面板。
     */
    private fun analyzeAllWindows(pkg: String): TreeInfo? {
        val roots = mutableListOf<AccessibilityNodeInfo>()
        fun addRoot(r: AccessibilityNodeInfo?) {
            r ?: return
            // 网页节点上报的就是宿主浏览器包名，所以按包名过滤是可靠的
            if (r.packageName?.toString() != pkg) return
            if (roots.any { it == r }) return
            roots += r
        }
        addRoot(rootInActiveWindow)
        runCatching { windows }.getOrNull()?.forEach { w -> addRoot(w.root) }
        if (roots.isEmpty()) return null
        val acc = AnalyzeAcc()
        roots.forEach { walk(it, pkg, 0, acc) }
        // 活动窗口与其他窗口可能是同一棵树的两份快照，去重后账号框/密码框才不会在
        // fields 里各出现两次（重复会让 resolveUsername 的"密码框前一个可编辑框"错位）。
        return TreeInfo(
            acc.fields.distinct(),
            acc.hasWebView,
            acc.bestDomain,
            acc.urlBarNode,
            acc.focusedEditable,
            roots.size,
        )
    }

    private fun walk(n: AccessibilityNodeInfo, pkg: String, depth: Int, acc: AnalyzeAcc) {
        if (depth > MAX_TREE_DEPTH || acc.visited > MAX_TREE_NODES) return
        acc.visited++

        val cls = n.className?.toString() ?: ""
        if (isWebViewNode(n)) acc.hasWebView = true

        // Chromium 把网页 <input> 映射成 android.widget.EditText；isEditable 在
        // 网页节点上不一定可靠，所以两个条件取或。
        //
        // 但 WebView 这个**容器**本身也会上报 isEditable/isFocused=true，必须排除：
        // 它是容器不是输入框，混进 fields 会顶替真正的密码框成为 focusedEditable，
        // 判定随即变成"聚焦的不是密码框"→ 面板永远不弹（实测 f=WebView#?）。
        if (isInputNode(n)) {
            acc.fields += n
            if (acc.focusedEditable == null && n.isFocused) acc.focusedEditable = n

            val text = n.text?.toString()?.trim()
            if (!text.isNullOrEmpty() && text.length in 4..512) {
                val idTail = n.viewIdResourceName?.substringAfterLast('/')?.lowercase().orEmpty()
                val pri = urlPriority(idTail, pkg)
                if (pri > acc.bestPriority) {
                    domainFromUrl(text)?.let {
                        acc.bestPriority = pri
                        acc.bestDomain = it
                        acc.urlBarNode = n
                    }
                }
            }
        }

        for (i in 0 until n.childCount) n.getChild(i)?.let { walk(it, pkg, depth + 1, acc) }
    }

    private fun describe(n: AccessibilityNodeInfo): String {
        val id = n.viewIdResourceName?.substringAfterLast('/').orEmpty()
        val hint = n.hintText?.toString().orEmpty()
        val cls = n.className?.toString()?.substringAfterLast('.').orEmpty()
        return "$cls#${id.ifEmpty { hint.ifEmpty { if (n.isPassword) "pwd" else "?" } }}"
    }

    // ------------------------------------------------------------------
    // 节点分类
    // ------------------------------------------------------------------

    /**
     * 是不是 WebView **容器**节点。
     *
     * 不能只比对 `android.webkit.WebView`：国产浏览器普遍换内核，小米浏览器走 X5/TBS，
     * 类名形如 `com.tencent.smtt.webkit.WebView`，只认 AOSP 那个全名会漏判。
     * 漏判的后果很重——容器会被当成输入框，顶替真正的密码框成为 focusedEditable，
     * 判定随即变成"聚焦的不是密码框"，面板就永远不弹了。
     */
    private fun isWebViewNode(n: AccessibilityNodeInfo): Boolean {
        val cls = n.className?.toString() ?: return false
        return cls == "android.webkit.WebView" || cls.endsWith(".WebView")
    }

    /** 是不是真正可填写的输入框（排除 WebView / FrameLayout 这类容器）。 */
    private fun isInputNode(n: AccessibilityNodeInfo): Boolean {
        if (isWebViewNode(n)) return false
        return n.isEditable || n.className?.toString() == "android.widget.EditText"
    }

    // ------------------------------------------------------------------
    // 字段语义判定
    // ------------------------------------------------------------------

    private fun isUrlBar(n: AccessibilityNodeInfo, pkg: String): Boolean {
        val idTail = n.viewIdResourceName?.substringAfterLast('/')?.lowercase().orEmpty()
        return urlPriority(idTail, pkg) >= URL_BAR_MIN_PRIORITY
    }

    private fun isPasswordField(n: AccessibilityNodeInfo): Boolean {
        if (n.isPassword) return true
        val hay = (
            (n.hintText?.toString() ?: "") + " " +
                (n.contentDescription?.toString() ?: "") + " " +
                (n.viewIdResourceName ?: "")
            ).lowercase()
        return PASSWORD_HINTS.any { hay.contains(it) }
    }

    private fun isUsernameField(n: AccessibilityNodeInfo): Boolean {
        if (isPasswordField(n)) return false
        val hay = (
            (n.hintText?.toString() ?: "") + " " +
                (n.contentDescription?.toString() ?: "") + " " +
                (n.viewIdResourceName ?: "")
            ).lowercase()
        return USERNAME_HINTS.any { hay.contains(it) }
    }

    // ------------------------------------------------------------------
    // 匹配
    // ------------------------------------------------------------------

    private fun matchItems(
        repo: VaultRepository,
        domain: String?,
        pkg: String,
        isWeb: Boolean,
    ): List<ItemWithPlain> {
        val all = repo.items.value
        if (all.isEmpty()) return emptyList()
        if (domain != null) {
            return all.filter { item ->
                val host = hostOf(item.plain.url) ?: return@filter false
                etldPlusOne(host) == domain
            }.sortedByDescending { it.entity.favorite }
        }
        // 拿不到地址栏（或还没解析出域名）：Web 场景下不做包名匹配，
        // 否则会把某个 App 的条目错误地填进网页。
        if (isWeb) return emptyList()
        return all.filter { it.plain.url.trim() == pkg }.sortedByDescending { it.entity.favorite }
    }

    private fun hostOf(url: String): String? {
        val u = url.trim()
        if (u.isEmpty() || u.startsWith("androidapp://")) return null
        return try {
            if (u.contains("://")) java.net.URI(u).host?.lowercase()
            else u.substringBefore('/').substringBefore(':').lowercase().ifEmpty { null }
        } catch (_: Exception) {
            null
        }
    }

    private fun domainFromUrl(raw: String): String? {
        val t = raw.trim()
        if (t.isEmpty() || t.length > 512) return null
        val lowered = t.lowercase()
        if (lowered.startsWith("search") || lowered.contains("搜索") || lowered.contains(" ")) return null
        val s = if (t.contains("://")) t else "https://$t"
        val host = try {
            java.net.URI(s).host
        } catch (_: Exception) {
            null
        } ?: return null
        if (!host.contains('.') || host.length > 253) return null
        return etldPlusOne(host)
    }

    private fun urlPriority(idTail: String, pkg: String): Int {
        if (idTail.isEmpty()) return 0
        KNOWN_URL_BAR_IDS[pkg]?.let { if (idTail == it) return 100 }
        return when {
            idTail == "url_bar" || idTail == "url" || idTail == "omnibox" -> 90
            idTail.contains("url_bar") || idTail.contains("urlbar") -> 85
            idTail.endsWith("url") || idTail.startsWith("url") -> 70
            idTail.contains("omnibox") -> 65
            idTail.contains("location_bar") || idTail.contains("locationbar") -> 60
            idTail.contains("address") && idTail.contains("bar") -> 55
            else -> 0
        }
    }

    // ------------------------------------------------------------------
    // 悬浮面板
    // ------------------------------------------------------------------

    private class PanelState(
        val pkg: String,
        val domain: String?,
        val fields: FieldSet,
        val rows: List<Row>,
    )

    private class Row(val label: String, val action: RowAction)

    private sealed interface RowAction {
        data class Fill(val item: ItemWithPlain) : RowAction
        data object Unlock : RowAction
        data object Create : RowAction
    }

    private fun showPanel(anchor: Rect) {
        val state = panelState ?: return
        dismissPanel()
        val ctx = this
        val night = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES
        val bgColor = if (night) 0xFF2A2A31.toInt() else 0xFFFFFFFF.toInt()
        val fgColor = if (night) 0xFFF2F2F7.toInt() else 0xFF1B1B1F.toInt()
        val strokeColor = if (night) 0x33FFFFFF else 0x22000000

        val card = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(bgColor, strokeColor)
            setPadding(dp(4), dp(4), dp(4), dp(4))
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
        }

        for (row in state.rows) {
            val tv = TextView(ctx).apply {
                text = row.label
                setTextColor(fgColor)
                textSize = 15f
                maxLines = 1
                ellipsize = android.text.TextUtils.TruncateAt.END
                setPadding(dp(12), dp(11), dp(12), dp(11))
                background = pressable(night)
                isClickable = true
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
                setOnClickListener {
                    AutofillDiag.log("无障碍：点击候选项「${row.label}」")
                    onRowClicked(row)
                }
            }
            card.addView(
                tv,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ),
            )
        }

        val screenW = resources.displayMetrics.widthPixels
        val screenH = resources.displayMetrics.heightPixels

        // 与输入框对齐：左边缘取输入框左边缘、宽度取输入框宽度，视觉上就是挂在输入框下面。
        // 都要夹进屏幕安全区——输入框贴边或宽过屏幕时，面板不能跟着跑出屏幕外。
        // 下限保证窄输入框下面也放得下文字，不至于被 ellipsize 截断。
        val margin = dp(8)
        val maxW = (screenW - margin * 2).coerceAtLeast(dp(120))
        val minW = min(dp(160), maxW)
        val width = anchor.width().coerceIn(minW, maxW)
        val x = anchor.left.coerceIn(margin, (screenW - margin - width).coerceAtLeast(margin))

        val params = WindowManager.LayoutParams(
            width,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            this.x = x
            y = anchor.bottom + dp(6)
        }

        card.setOnTouchListener { _, e ->
            if (e.action == android.view.MotionEvent.ACTION_OUTSIDE) {
                dismissPanel("点击面板外部")
                // 用户主动关掉面板 = 这次填充尝试结束，下次点密码框允许再试一次免解锁
                autoUnlockAttempted = false
                true
            } else {
                false
            }
        }

        // 无障碍服务的窗口 token 会在服务被重新连接时失效（实测报
        // "Unable to add window -- token ... is not valid"）。此时重新取一次
        // WindowManager 再试一遍，避免偶发的"面板死活弹不出来"。
        if (!addOverlay(card, params)) {
            wm = getSystemService(WINDOW_SERVICE) as WindowManager
            if (!addOverlay(card, params)) {
                AutofillDiag.log("无障碍：面板添加失败，放弃本次展示")
                return
            }
            AutofillDiag.log("无障碍：面板在重建 WindowManager 后添加成功")
        }
        panel = card

        // 贴底时翻到输入框上方
        card.post {
            val v = panel ?: return@post
            if (v.height <= 0) return@post
            val limit = screenH - dp(64)
            if (params.y + v.height > limit) {
                val above = anchor.top - v.height - dp(6)
                params.y = if (above > dp(8)) above else (limit - v.height).coerceAtLeast(dp(8))
                runCatching { wm.updateViewLayout(v, params) }
            }
        }
        lastShownAt = System.currentTimeMillis()
        AutofillDiag.log(
            "无障碍：已弹出面板（${state.rows.size} 项，anchor=${anchor.toShortString()} " +
                "x=$x w=$width）",
        )
    }

    private fun addOverlay(view: View, params: WindowManager.LayoutParams): Boolean = try {
        wm.addView(view, params)
        true
    } catch (e: Exception) {
        AutofillDiag.log("无障碍：addView 失败 ${e.message}")
        false
    }

    /**
     * 只负责把窗口移除。**不清 lastKey**：否则 showPanel() 内部的先删后加会把
     * evaluate() 刚写入的去重键抹掉，导致同一字段的事件反复重建面板（闪烁）。
     */
    private fun dismissPanel(reason: String? = null) {
        val v = panel ?: return
        panel = null
        if (reason != null) AutofillDiag.log("无障碍：收起面板（$reason）")
        runCatching { wm.removeViewImmediate(v) }
    }

    private fun teardown() {
        dismissPanel()
        lastKey = null
        panelState = null
        pendingRetry = null
        autoUnlockAttempted = false
        ioScope?.cancel()
        ioScope = null
        mainHandler.removeCallbacksAndMessages(null)
        debugReceiver?.let { runCatching { unregisterReceiver(it) } }
        debugReceiver = null
    }

    private fun rounded(fill: Int, stroke: Int): GradientDrawable = GradientDrawable().apply {
        cornerRadius = dp(14).toFloat()
        setColor(fill)
        setStroke(dp(1), stroke)
    }

    private fun pressable(night: Boolean): StateListDrawable {
        val pressed = GradientDrawable().apply {
            cornerRadius = dp(10).toFloat()
            setColor(if (night) 0x22FFFFFF else 0x14000000)
        }
        return StateListDrawable().apply {
            addState(intArrayOf(android.R.attr.state_pressed), pressed)
            addState(intArrayOf(), rounded(0, 0))
        }
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    // ------------------------------------------------------------------
    // 动作
    // ------------------------------------------------------------------

    private fun onRowClicked(row: Row) {
        val state = panelState
        dismissPanel()
        when (val a = row.action) {
            is RowAction.Unlock -> {
                pendingRetry = PendingRetry(state?.pkg ?: "", state?.domain)
                val intent = Intent(this, UnlockActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    putExtra(UnlockActivity.EXTRA_AUTOFILL_MODE, false)
                }
                runCatching { startActivity(intent) }
                    .onFailure { AutofillDiag.log("无障碍：拉起解锁页失败 ${it.message}") }
            }

            is RowAction.Create -> {
                val target = state?.domain?.let { "https://$it" }
                    ?: state?.pkg?.let { "androidapp://$it" }
                    ?: ""
                val intent = Intent(this, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    action = ZpasswdAutofillService.ACTION_AUTOFILL_NEW
                    putExtra(ZpasswdAutofillService.EXTRA_AUTOFILL_TARGET, target)
                }
                runCatching { startActivity(intent) }
            }

            is RowAction.Fill -> {
                val fields = state?.fields ?: return
                fill(a.item, fields, state.pkg)
            }
        }
    }

    private fun fill(item: ItemWithPlain, fields: FieldSet, pkg: String) {
        // WebView 的节点实例可能已经失效（页面重渲染），优先用现场重新解析出来的节点。
        // 用跨窗口遍历，避免输入法弹起时只拿到局部树（见 analyzeAllWindows 注释）。
        val fresh = analyzeAllWindows(pkg)?.fields.orEmpty()
        val liveFields = if (fresh.isNotEmpty()) {
            val pw = fresh.firstOrNull { isPasswordField(it) } ?: fields.password
            val urlBar = fresh.firstOrNull { isUrlBar(it, pkg) }
            FieldSet(resolveUsername(fresh, pw, urlBar, pw), pw)
        } else {
            fields
        }

        var ok = 0
        liveFields.username?.let { if (fillNode(it, item.plain.username)) ok++ }
        liveFields.password?.let { if (fillNode(it, item.plain.password)) ok++ }

        if (ok == 0) {
            copyToClipboard(item.plain.password)
            AutofillDiag.log("无障碍：填充失败，密码已复制到剪贴板")
        } else {
            AutofillDiag.log(
                "无障碍：已填充 $ok 个字段（${item.plain.name.ifBlank { item.plain.username }}）",
            )
        }
    }

    private fun fillNode(node: AccessibilityNodeInfo, value: String): Boolean {
        if (value.isEmpty()) return false
        runCatching { node.performAction(AccessibilityNodeInfo.ACTION_FOCUS) }
        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value)
        }
        if (runCatching { node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args) }
                .getOrDefault(false)
        ) {
            return true
        }
        // Chromium 部分版本不接受 ACTION_SET_TEXT：退回剪贴板粘贴
        return try {
            copyToClipboard(value)
            node.performAction(AccessibilityNodeInfo.ACTION_PASTE)
        } catch (_: Exception) {
            false
        }
    }

    private fun copyToClipboard(value: String) {
        runCatching {
            val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("zpasswd", value))
        }
    }

    private fun labelOf(item: ItemWithPlain): String {
        val name = item.plain.name.ifBlank { hostOf(item.plain.url).orEmpty().ifBlank { "zpasswd" } }
        val user = item.plain.username
        return if (user.isBlank()) name else "$name · $user"
    }

    // ------------------------------------------------------------------
    // 解锁回来后重试
    // ------------------------------------------------------------------

    private class PendingRetry(val pkg: String, val domain: String?)

    private fun retryIfPending(pkg: String) {
        val p = pendingRetry ?: return
        if (p.pkg.isNotEmpty() && pkg != p.pkg) return
        if (!VaultRepository.get(this).isUnlocked()) return
        pendingRetry = null
        // 解锁页关闭、浏览器回到前台，此时节点树已就绪，重新评估一次
        mainHandler.postDelayed({
            if (pkg == packageName) return@postDelayed
            // 回来时 Chromium 不一定还保留焦点，允许无焦点兜底
            evaluate(pkg, null, allowUnfocused = true)
        }, 350)
    }

    // ------------------------------------------------------------------
    // 调试通道（仅 debuggable 构建注册）
    // ------------------------------------------------------------------

    private fun registerDebugReceiverIfDebuggable() {
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!debuggable) return
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, intent: Intent?) {
                when (intent?.action) {
                    ACTION_DEBUG_FILL -> {
                        val idx = intent.getIntExtra("index", 0)
                        val row = panelState?.rows?.getOrNull(idx)
                        AutofillDiag.log("调试：触发填充 index=$idx row=${row?.label ?: "null"}")
                        if (row != null) onRowClicked(row)
                    }
                    ACTION_DEBUG_DUMP -> dumpTree()
                    ACTION_DEBUG_SETTEXT -> debugSetText(intent)
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(ACTION_DEBUG_FILL)
            addAction(ACTION_DEBUG_DUMP)
            addAction(ACTION_DEBUG_SETTEXT)
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= 33) {
                // 必须 EXPORTED 才能用 `adb shell am broadcast` 触发（shell 是别的 uid）。
                // 只在 debuggable 构建注册，正式包没有这个接收器。
                registerReceiver(r, filter, Context.RECEIVER_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                registerReceiver(r, filter)
            }
            debugReceiver = r
            AutofillDiag.log("无障碍：调试通道已注册（$ACTION_DEBUG_FILL / $ACTION_DEBUG_SETTEXT / $ACTION_DEBUG_DUMP）")
        }
    }

    /**
     * 直接把一段文字写进当前页面的输入框，绕过 vault。
     *
     * 用途：验证「能不能把值写进 Chromium 的网页输入框」这一最后环节。
     * 部分设备无法注入触摸事件（HyperOS 禁止 `adb shell input`），
     * 没法靠点面板来验证填充，这个通道可以在不依赖触摸的情况下跑通写入链路。
     * 仅 debuggable 构建注册。
     */
    private fun debugSetText(intent: Intent) {
        val target = intent.getStringExtra("target") ?: "password"
        val text = intent.getStringExtra("text") ?: "zpasswd-probe"
        val root = rootInActiveWindow ?: run {
            AutofillDiag.log("调试：无窗口节点树")
            return
        }
        val fields = analyze(root, packageName).fields
        val node = if (target == "password") {
            fields.firstOrNull { isPasswordField(it) }
        } else {
            fields.firstOrNull { !isPasswordField(it) && !isUrlBar(it, packageName) }
        }
        if (node == null) {
            AutofillDiag.log("调试：未找到 $target 输入框（共 ${fields.size} 个可编辑节点）")
            return
        }
        val ok = fillNode(node, text)
        AutofillDiag.log("调试：写入 $target = 「$text」 → ${if (ok) "成功" else "失败"}")
    }

    private fun dumpTree() {
        val root = rootInActiveWindow ?: return
        val sb = StringBuilder()
        fun walk(n: AccessibilityNodeInfo, depth: Int) {
            if (depth > 24) return
            val cls = n.className?.toString()?.substringAfterLast('.').orEmpty()
            if (n.isEditable || cls == "WebView") {
                sb.append("\n  ").append("·".repeat(depth))
                    .append(cls).append(" id=").append(n.viewIdResourceName?.substringAfterLast('/'))
                    .append(" pwd=").append(n.isPassword)
                    .append(" focus=").append(n.isFocused)
                    .append(" txt=").append(n.text?.toString()?.take(40))
            }
            for (i in 0 until n.childCount) n.getChild(i)?.let { walk(it, depth + 1) }
        }
        walk(root, 0)
        AutofillDiag.log("调试：节点树$sb")
    }

    companion object {
        private const val CONTENT_EVENT_THROTTLE_MS = 700L
        private const val PANEL_DEBOUNCE_MS = 500L
        private const val MAX_ROWS = 3
        private const val MAX_TREE_DEPTH = 60
        private const val MAX_TREE_NODES = 4000
        private const val URL_BAR_MIN_PRIORITY = 55

        const val ACTION_DEBUG_FILL = "dev.zpasswd.app.DEBUG_FILL"
        const val ACTION_DEBUG_DUMP = "dev.zpasswd.app.DEBUG_DUMP"
        const val ACTION_DEBUG_SETTEXT = "dev.zpasswd.app.DEBUG_SETTEXT"

        @Volatile
        private var instance: ZpasswdAccessibilityService? = null

        /** 服务是否已在系统无障碍设置里启用。 */
        fun isEnabled(context: Context): Boolean {
            val expected = ComponentName(
                context.packageName,
                ZpasswdAccessibilityService::class.java.name,
            )
            val raw = try {
                Settings.Secure.getString(
                    context.contentResolver,
                    Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
                )
            } catch (_: Exception) {
                null
            } ?: return false
            return raw.split(':').any {
                it.equals(expected.flattenToString(), ignoreCase = true) ||
                    it.equals(expected.flattenToShortString(), ignoreCase = true)
            }
        }

        /** 无障碍总闸（设置 → 无障碍）是否打开。 */
        fun isAccessibilityOn(context: Context): Boolean = try {
            Settings.Secure.getInt(context.contentResolver, Settings.Secure.ACCESSIBILITY_ENABLED) == 1
        } catch (_: Exception) {
            false
        }

        /** 是否已启用无障碍自动填充（总闸 + 本服务都在）。 */
        fun isAutofillEnabled(context: Context): Boolean =
            isAccessibilityOn(context) && isEnabled(context)

        /** 已知浏览器包名：这些包即使节点树里暂时没扫到 WebView 也允许介入。 */
        private val BROWSER_PACKAGES = setOf(
            "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary",
            "com.microsoft.emmx", "com.brave.browser", "com.opera.browser",
            "com.opera.mini.native", "com.opera.gx", "com.sec.android.app.sbrowser",
            "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.focus",
            "com.android.browser", "com.miui.browser", "com.quark.browser", "com.UCMobile",
            "com.tencent.mtt", "com.baidu.searchbox", "com.heytap.browser", "com.vivo.browser",
            "com.huawei.browser", "com.kiwibrowser.browser", "com.duckduckgo.mobile.android",
            "com.yandex.browser", "com.ecosia.android", "com.vivaldi.browser",
            "com.qihoo.browser", "com.oupeng.browser", "mark.via", "com.uc.browser",
            "com.transsion.phoenix",
        )

        /** 系统瞬时窗口：出现时不应把填充面板收掉（否则会闪）。 */
        private val TRANSIENT_WINDOW_PKGS = setOf(
            "android", "com.android.systemui", "com.miui.personalassistant",
            "com.miui.notification", "com.miui.aod", "com.miui.toast",
            "com.android.permissioncontroller", "com.miui.securitycenter",
        )

        /** 各家浏览器的地址栏资源 id（取 `/` 之后的末段，小写）。 */
        private val KNOWN_URL_BAR_IDS = mapOf(
            "com.android.chrome" to "url_bar",
            "com.chrome.beta" to "url_bar",
            "com.microsoft.emmx" to "url_bar",
            "com.brave.browser" to "url_bar",
            "com.vivaldi.browser" to "url_bar",
            "com.android.browser" to "url",
            "com.miui.browser" to "url",
            "org.mozilla.firefox" to "mozac_browser_toolbar_url_view",
            "com.sec.android.app.sbrowser" to "location_bar_edit_text",
            "com.opera.browser" to "url_field",
        )

        private val PASSWORD_HINTS = listOf(
            "password", "passwd", "pwd", "passcode", "passphrase", "密码", "口令",
        )

        private val USERNAME_HINTS = listOf(
            "username", "user_name", "userid", "user_id", "user name", "login",
            "email", "e-mail", "account", "phone", "mobile", "tel",
            "用户名", "账号", "帐号", "邮箱", "手机号", "手机", "登录名",
        )
    }
}
