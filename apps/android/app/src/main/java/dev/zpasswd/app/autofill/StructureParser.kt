package dev.zpasswd.app.autofill

import android.app.assist.AssistStructure
import android.os.Build
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
    fun parse(structure: AssistStructure): ParsedForm? {
        val nodes = structure.windowNodeCount
        var pkg = ""
        var webDomain: String? = null
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        val fillable = mutableListOf<AutofillId>()
        val values = mutableMapOf<AutofillId, String>()

        for (i in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(i)
            val root = window.rootViewNode ?: continue
            if (pkg.isEmpty()) pkg = root.packageName?.toString() ?: ""
            walk(root, object : NodeVisitor {
                override fun visit(node: AssistStructure.ViewNode) {
                    val id = node.autofillId ?: return
                    // WebView 场景：webDomain
                    if (Build.VERSION.SDK_INT >= 26) {
                        node.webDomain?.let { if (webDomain == null) webDomain = it }
                    }
                    val hints = node.autofillHints ?: emptyArray()
                    val hintSet = hints.map { it.lowercase() }.toSet()
                    val inputType = node.inputType

                    val isPassword = "password" in hintSet ||
                        (inputType and android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD) != 0 ||
                        (inputType and android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD) != 0
                    val isUsername = ("username" in hintSet || "emailaddress" in hintSet ||
                        "email" in hintSet) && !isPassword

                    if (isPassword && passwordId == null) passwordId = id
                    if (isUsername && usernameId == null) usernameId = id
                    if (node.autofillType == android.view.View.AUTOFILL_TYPE_TEXT) {
                        if (id !in fillable) fillable.add(id)
                        node.autofillValue?.let { v ->
                            if (v.isText) values[id] = v.textValue?.toString() ?: ""
                        }
                    }
                }
            })
        }
        if (passwordId == null && usernameId == null && fillable.isEmpty()) return null
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
