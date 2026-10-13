package dev.zpasswd.app.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue

/** 从 AssistStructure 解析出的登录表单信息。 */
data class ParsedForm(
    val packageName: String,
    /** Web 场景的域名（如 github.com），App 场景为 null */
    val webDomain: String?,
    val usernameId: AutofillId?,
    val passwordId: AutofillId?,
    /** 所有可填充的文本框（用户名/密码/其他） */
    val fillableIds: List<AutofillId>,
    /** 用于 save 的已有值 */
    val currentValues: Map<AutofillId, String>,
)

object StructureParser {
    /**
     * 用户名/账号类字段的 id / hint 关键词（中英文）。
     * 很多 App 既不设 autofillHints，inputType 也和普通文本框一致，
     * 只能靠控件 id 或 hint 文案兜底识别。
     */
    private val USERNAME_KEYWORDS = listOf(
        "username", "user_name", "userid", "user_id", "user",
        "email", "mail", "phone", "mobile", "account", "login", "tel",
        "用户名", "账号", "帐号", "邮箱", "手机", "电话",
    )

    fun parse(structure: AssistStructure): ParsedForm? {
        var webDomain: String? = null
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        val fillable = mutableListOf<AutofillId>()
        val values = mutableMapOf<AutofillId, String>()
        // 诊断用：记录每个文本框的识别依据，便于在 logcat / App 诊断页定位"为什么不弹"
        val debugFields = mutableListOf<String>()

        // 请求方包名：ViewNode 没有 packageName 属性，从 AssistStructure.activityComponent 取
        val pkg = structure.activityComponent?.packageName ?: ""
        for (i in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(i)
            val root = window.rootViewNode ?: continue
            walk(root, object : NodeVisitor {
                override fun visit(node: AssistStructure.ViewNode) {
                    val id = node.autofillId ?: return
                    // WebView 场景：webDomain（API 28+ 才有 getWebDomain）
                    if (Build.VERSION.SDK_INT >= 28) {
                        node.webDomain?.let { if (webDomain == null) webDomain = it }
                    }
                    val isTextField = node.autofillType == View.AUTOFILL_TYPE_TEXT
                    val hints = node.autofillHints ?: emptyArray()
                    val hintSet = hints.map { it.lowercase() }.toSet()
                    // 只看 variation 位：原实现直接 `inputType and TYPE_TEXT_VARIATION_PASSWORD`，
                    // 会把 TYPE_TEXT_VARIATION_WEB_EDIT_TEXT(0xa0) 这类普通文本框误判成密码框，
                    // 从而"任何输入框都弹"。
                    val variation = node.inputType and InputType.TYPE_MASK_VARIATION

                    val isPassword = isTextField && (
                        hintSet.any { it.contains("password") } ||
                            variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                            variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
                            variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                            variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
                        )

                    val hasUsernameHint = hintSet.any {
                        it.contains("username") || it.contains("email") ||
                            it.contains("phone") || it.contains("account")
                    }
                    val keyText = ((node.idEntry ?: "") + " " + (node.hint?.toString() ?: "")).lowercase()
                    val isUsername = isTextField && !isPassword &&
                        (hasUsernameHint || USERNAME_KEYWORDS.any { keyText.contains(it) })

                    if (isPassword && passwordId == null) passwordId = id
                    if (isUsername && usernameId == null) usernameId = id
                    if (isTextField) {
                        if (debugFields.size < 12) {
                            val name = node.idEntry
                                ?: node.hint?.toString()
                                ?: node.className?.toString()?.substringAfterLast('.')
                                ?: "?"
                            val tag = when {
                                isPassword -> "→密码"
                                isUsername -> "→用户名"
                                else -> ""
                            }
                            debugFields += "$name[v=0x${Integer.toHexString(variation)}," +
                                "hint=${hints.joinToString("|")}$tag]"
                        }
                        if (id !in fillable) fillable.add(id)
                        node.autofillValue?.let { v ->
                            if (v.isText) values[id] = v.textValue?.toString() ?: ""
                        }
                    }
                }
            })
        }
        // 只在疑似登录表单时介入：必须识别到密码框或用户名框。
        // 否则（搜索框、评论框、验证码框等）返回 null，系统就不会弹出填充面板——
        // 这正是把"任何输入框都弹"收紧为"只在登录框弹"的正确判据。
        if (passwordId == null && usernameId == null) {
            AutofillDiag.log("字段(未识别为登录框): ${debugFields.joinToString(" ")}")
            return null
        }
        AutofillDiag.log("字段: ${debugFields.joinToString(" ")}")
        return ParsedForm(pkg, webDomain, usernameId, passwordId, fillable, values)
    }

    private interface NodeVisitor {
        fun visit(node: AssistStructure.ViewNode)
    }

    private fun walk(node: AssistStructure.ViewNode, visitor: NodeVisitor) {
        visitor.visit(node)
        for (i in 0 until node.childCount) {
            node.getChildAt(i)?.let { walk(it, visitor) }
        }
    }
}

/** 简单 eTLD+1 近似：取最后两段（与扩展端逻辑对齐；扩展端用完整 eTLD+1，此处近似足够匹配用）。 */
fun etldPlusOne(host: String): String {
    val h = host.lowercase().trimEnd('.')
    // 常见双后缀
    val twoLevel = setOf("co.uk", "com.cn", "net.cn", "org.cn", "co.jp", "com.au")
    val parts = h.split(".")
    if (parts.size <= 2) return h
    val last2 = parts.takeLast(2).joinToString(".")
    return if (last2 in twoLevel && parts.size >= 3) parts.takeLast(3).joinToString(".") else last2
}
