package dev.zpasswd.app.ui

@file:OptIn(ExperimentalMaterial3Api::class)

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import dev.zpasswd.app.autofill.PendingCredential
import dev.zpasswd.app.biometric.BiometricUnlock
import dev.zpasswd.app.crypto.RecoveryCode
import dev.zpasswd.app.crypto.Totp
import dev.zpasswd.app.crypto.ZpCrypto
import dev.zpasswd.app.data.MetaEntity
import dev.zpasswd.app.data.VaultItemPlain
import dev.zpasswd.app.data.VaultRepository
import dev.zpasswd.app.sync.SyncEngine
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// ---------------------------------------------------------------------------
// 通用小组件
// ---------------------------------------------------------------------------

@Composable
private fun SectionTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(vertical = 8.dp),
    )
}

@Composable
private fun ErrorText(msg: String?) {
    if (!msg.isNullOrEmpty()) {
        Text(
            text = msg,
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp),
        )
    }
}

private fun toast(activity: FragmentActivity, msg: String) {
    Toast.makeText(activity, msg, Toast.LENGTH_LONG).show()
}

// ---------------------------------------------------------------------------
// 1. 解锁 / 创建
// ---------------------------------------------------------------------------

@Composable
fun UnlockScreen(
    activity: FragmentActivity,
    repo: VaultRepository,
    onUnlocked: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(true) } // 正在判断是否已有 vault
    var hasVault by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var bioEnrolled by remember { mutableStateOf(false) }
    val context = LocalContext.current

    LaunchedEffect(Unit) {
        hasVault = withContext(Dispatchers.IO) { repo.hasVault() }
        bioEnrolled = withContext(Dispatchers.IO) { BiometricUnlock.isEnrolled(repo) }
        loading = false
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("zpasswd", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(24.dp))

            when {
                loading -> CircularProgressIndicator()
                !hasVault -> CreateVaultForm(
                    busy = busy,
                    error = error,
                    onCreate = { pw ->
                        error = null
                        busy = true
                        scope.launch(Dispatchers.IO) {
                            try {
                                repo.createVault(pw)
                                withContext(Dispatchers.Main) { onUnlocked() }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    error = e.message ?: "创建失败"
                                    busy = false
                                }
                            }
                        }
                    },
                )
                else -> UnlockForm(
                    busy = busy,
                    error = error,
                    showFingerprint = bioEnrolled && BiometricUnlock.isAvailable(context),
                    onUnlock = { pw ->
                        error = null
                        busy = true
                        scope.launch(Dispatchers.IO) {
                            try {
                                repo.unlock(pw)
                                withContext(Dispatchers.Main) { onUnlocked() }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    error = "主密码不正确"
                                    busy = false
                                }
                            }
                        }
                    },
                    onFingerprint = {
                        BiometricUnlock.authenticate(
                            activity, repo,
                            onSuccess = { onUnlocked() },
                            onError = { msg -> error = msg },
                        )
                    },
                )
            }
        }
    }
}

@Composable
private fun CreateVaultForm(
    busy: Boolean,
    error: String?,
    onCreate: (String) -> Unit,
) {
    var pw1 by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var localError by remember { mutableStateOf<String?>(null) }

    Text("创建保险库", style = MaterialTheme.typography.titleLarge)
    Text(
        "主密码是唯一能解密数据的钥匙，请牢记。创建后请到设置页抄写恢复码。",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(vertical = 8.dp),
    )
    PasswordField(value = pw1, onValueChange = { pw1 = it }, label = "主密码（至少 12 位）")
    Spacer(Modifier.height(8.dp))
    PasswordField(value = pw2, onValueChange = { pw2 = it }, label = "再次输入主密码")
    ErrorText(localError ?: error)
    Spacer(Modifier.height(16.dp))
    Button(
        onClick = {
            localError = when {
                pw1.length < 12 -> "主密码至少 12 位"
                pw1 != pw2 -> "两次输入不一致"
                else -> null
            }
            if (localError == null) onCreate(pw1)
        },
        enabled = !busy,
        modifier = Modifier.fillMaxWidth(),
    ) {
        if (busy) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            Spacer(Modifier.width(8.dp))
        }
        Text(if (busy) "创建中（约 1-2 秒）…" else "创建保险库")
    }
}

@Composable
private fun UnlockForm(
    busy: Boolean,
    error: String?,
    showFingerprint: Boolean,
    onUnlock: (String) -> Unit,
    onFingerprint: () -> Unit,
) {
    var pw by remember { mutableStateOf("") }

    Text("解锁保险库", style = MaterialTheme.typography.titleLarge)
    Spacer(Modifier.height(8.dp))
    PasswordField(value = pw, onValueChange = { pw = it }, label = "主密码")
    ErrorText(error)
    Spacer(Modifier.height(16.dp))
    Button(
        onClick = { onUnlock(pw) },
        enabled = !busy && pw.isNotEmpty(),
        modifier = Modifier.fillMaxWidth(),
    ) {
        if (busy) {
            CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
            Spacer(Modifier.width(8.dp))
        }
        Text(if (busy) "解锁中（约 1-2 秒）…" else "解锁")
    }
    if (showFingerprint) {
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = onFingerprint,
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Filled.Fingerprint, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("指纹解锁")
        }
    }
}

@Composable
private fun PasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = modifier.fillMaxWidth(),
        singleLine = true,
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        trailingIcon = {
            IconButton(onClick = { visible = !visible }) {
                Icon(
                    if (visible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                    contentDescription = if (visible) "隐藏" else "显示",
                )
            }
        },
    )
}

// ---------------------------------------------------------------------------
// 2. 条目列表
// ---------------------------------------------------------------------------

@Composable
fun VaultListScreen(
    repo: VaultRepository,
    pendingSave: PendingCredential?,
    onItemClick: (String) -> Unit,
    onAdd: () -> Unit,
    onSettings: () -> Unit,
    onPendingSaveConsumed: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val items by repo.items.collectAsState()
    var query by remember { mutableStateOf("") }

    val filtered = remember(items, query) {
        val q = query.trim().lowercase()
        if (q.isEmpty()) items
        else items.filter {
            it.plain.name.lowercase().contains(q) ||
                it.plain.username.lowercase().contains(q) ||
                it.plain.url.lowercase().contains(q)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("保险库") },
                actions = {
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Filled.Settings, contentDescription = "设置")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAdd) {
                Icon(Icons.Filled.Add, contentDescription = "新建条目")
            }
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            // 待保存凭证横幅
            if (pendingSave != null) {
                PendingSaveBanner(
                    pending = pendingSave,
                    onSave = {
                        val url = pendingSave.webDomain
                            ?: "androidapp://${pendingSave.packageName}"
                        val name = pendingSave.webDomain ?: pendingSave.packageName
                        scope.launch(Dispatchers.IO) {
                            try {
                                repo.saveItem(
                                    id = null,
                                    plain = VaultItemPlain(
                                        name = name,
                                        username = pendingSave.username,
                                        password = pendingSave.password,
                                        url = url,
                                    ),
                                    folderId = null,
                                    favorite = false,
                                )
                            } finally {
                                withContext(Dispatchers.Main) { onPendingSaveConsumed() }
                            }
                        }
                    },
                    onDismiss = onPendingSaveConsumed,
                )
            }

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("搜索名称 / 用户名 / 网址") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                singleLine = true,
            )

            if (filtered.isEmpty()) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        if (items.isEmpty()) "暂无条目，点击右下角 + 新建"
                        else "没有匹配的条目",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(filtered, key = { it.entity.id }) { item ->
                        ItemRow(item = item, onClick = { onItemClick(item.entity.id) })
                    }
                }
            }
        }
    }
}

@Composable
private fun PendingSaveBanner(
    pending: PendingCredential,
    onSave: () -> Unit,
    onDismiss: () -> Unit,
) {
    var busy by remember { mutableStateOf(false) }
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "检测到新登录凭证：${pending.webDomain ?: pending.packageName}" +
                    (if (pending.username.isNotBlank()) "（${pending.username}）" else "") +
                    "，是否保存到保险库？",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                TextButton(
                    onClick = onDismiss,
                    enabled = !busy,
                ) { Text("忽略") }
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = { busy = true; onSave() },
                    enabled = !busy,
                ) {
                    Icon(Icons.Filled.Check, contentDescription = null)
                    Spacer(Modifier.width(4.dp))
                    Text("保存")
                }
            }
        }
    }
}

@Composable
private fun ItemRow(
    item: dev.zpasswd.app.data.ItemWithPlain,
    onClick: () -> Unit,
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    item.plain.name.ifBlank { "（无名称）" },
                    style = MaterialTheme.typography.titleMedium,
                )
                if (item.plain.username.isNotBlank()) {
                    Text(
                        item.plain.username,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. 条目详情
// ---------------------------------------------------------------------------

@Composable
fun ItemDetailScreen(
    repo: VaultRepository,
    itemId: String,
    onEdit: () -> Unit,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val items by repo.items.collectAsState()
    val item = items.find { it.entity.id == itemId }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    var pwVisible by remember { mutableStateOf(false) }

    LaunchedEffect(itemId) {
        if (item == null) withContext(Dispatchers.IO) { repo.refreshItems() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(item?.plain?.name?.ifBlank { "（无名称）" } ?: "加载中") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    IconButton(onClick = onEdit, enabled = item != null) {
                        Icon(Icons.Filled.Edit, contentDescription = "编辑")
                    }
                    IconButton(
                        onClick = { showDeleteConfirm = true },
                        enabled = item != null,
                    ) {
                        Icon(Icons.Filled.Delete, contentDescription = "删除")
                    }
                },
            )
        },
    ) { padding ->
        if (item == null) {
            Column(
                modifier = Modifier.fillMaxSize().padding(padding),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) { CircularProgressIndicator() }
        } else {
            val plain = item.plain
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
            ) {
                DetailField(label = "用户名", value = plain.username, copyable = true)
                DetailField(
                    label = "密码",
                    value = plain.password,
                    copyable = true,
                    masked = !pwVisible,
                    onToggleMask = { pwVisible = !pwVisible },
                )
                DetailField(label = "网址", value = plain.url, copyable = true)
                DetailField(label = "备注", value = plain.notes, copyable = false)
                if (plain.totpSeed.isNotBlank()) {
                    TotpView(seed = plain.totpSeed)
                }
            }
        }
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text("删除条目") },
            text = { Text("确定删除「${item?.plain?.name}」吗？删除后会同步到服务器。") },
            confirmButton = {
                TextButton(
                    onClick = {
                        showDeleteConfirm = false
                        scope.launch(Dispatchers.IO) {
                            try {
                                repo.deleteItem(itemId)
                                withContext(Dispatchers.Main) { onBack() }
                            } catch (_: Exception) { }
                        }
                    },
                ) { Text("删除", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) { Text("取消") }
            },
        )
    }
}

@Composable
private fun DetailField(
    label: String,
    value: String,
    copyable: Boolean,
    masked: Boolean = false,
    onToggleMask: (() -> Unit)? = null,
) {
    if (value.isBlank()) return
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    fun copyAndAutoClear(text: String) {
        clipboard.setText(AnnotatedString(text))
        scope.launch {
            delay(30_000)
            // 只有剪贴板仍是我们的内容时才清空
            if (clipboard.getText()?.text == text) {
                clipboard.setText(AnnotatedString(""))
            }
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(4.dp))
                SelectionContainer {
                    Text(
                        if (masked) "••••••••" else value,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
            if (onToggleMask != null) {
                IconButton(onClick = onToggleMask) {
                    Icon(
                        if (masked) Icons.Filled.Visibility else Icons.Filled.VisibilityOff,
                        contentDescription = if (masked) "显示密码" else "隐藏密码",
                    )
                }
            }
            if (copyable) {
                IconButton(onClick = { copyAndAutoClear(value) }) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "复制（30 秒后自动清除）")
                }
            }
        }
    }
}

@Composable
private fun TotpView(seed: String) {
    var tick by remember { mutableStateOf(0) }
    LaunchedEffect(seed) {
        while (true) {
            delay(1_000)
            tick++
        }
    }
    val code = remember(tick, seed) { runCatching { Totp.now(seed) }.getOrNull() }
    val remaining = remember(tick) { Totp.secondsRemaining() }

    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
            Text("动态验证码", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                val clipboard = LocalClipboardManager.current
                Text(
                    code ?: "密钥无效",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                if (code != null) {
                    IconButton(onClick = { clipboard.setText(AnnotatedString(code)) }) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "复制验证码")
                    }
                }
            }
            Text(
                if (code != null) "剩余 ${remaining} 秒" else "请检查 TOTP 密钥格式",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// 4. 条目编辑（含密码生成器）
// ---------------------------------------------------------------------------

@Composable
fun ItemEditScreen(
    repo: VaultRepository,
    itemId: String?,
    onDone: () -> Unit,
    onBack: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val items by repo.items.collectAsState()
    val existing = itemId?.let { id -> items.find { it.entity.id == id } }

    var name by remember(existing) { mutableStateOf(existing?.plain?.name ?: "") }
    var username by remember(existing) { mutableStateOf(existing?.plain?.username ?: "") }
    var password by remember(existing) { mutableStateOf(existing?.plain?.password ?: "") }
    var url by remember(existing) { mutableStateOf(existing?.plain?.url ?: "") }
    var notes by remember(existing) { mutableStateOf(existing?.plain?.notes ?: "") }
    var totpSeed by remember(existing) { mutableStateOf(existing?.plain?.totpSeed ?: "") }
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (itemId == null) "新建条目" else "编辑条目") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    TextButton(
                        onClick = {
                            if (name.isBlank() && username.isBlank()) {
                                error = "名称和用户名至少填一个"
                                return@TextButton
                            }
                            error = null
                            saving = true
                            scope.launch(Dispatchers.IO) {
                                try {
                                    repo.saveItem(
                                        id = itemId,
                                        plain = VaultItemPlain(
                                            name = name,
                                            username = username,
                                            password = password,
                                            url = url,
                                            notes = notes,
                                            totpSeed = totpSeed.trim().replace(" ", ""),
                                        ),
                                        folderId = existing?.entity?.folderId,
                                        favorite = existing?.entity?.favorite ?: false,
                                    )
                                    withContext(Dispatchers.Main) { onDone() }
                                } catch (e: Exception) {
                                    withContext(Dispatchers.Main) {
                                        error = e.message ?: "保存失败"
                                        saving = false
                                    }
                                }
                            }
                        },
                        enabled = !saving,
                    ) {
                        if (saving) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        else Text("保存")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("名称") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(value = username, onValueChange = { username = it }, label = { Text("用户名") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("密码") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(value = url, onValueChange = { url = it }, label = { Text("网址") },
                modifier = Modifier.fillMaxWidth(), singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(value = totpSeed, onValueChange = { totpSeed = it }, label = { Text("TOTP 密钥（可选）") },
                modifier = Modifier.fillMaxWidth(), singleLine = true)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(value = notes, onValueChange = { notes = it }, label = { Text("备注") },
                modifier = Modifier.fillMaxWidth(), minLines = 3)
            ErrorText(error)
            Spacer(Modifier.height(16.dp))
            SectionTitle("密码生成器")
            PasswordGenerator(onUse = { password = it })
        }
    }
}

@Composable
private fun PasswordGenerator(onUse: (String) -> Unit) {
    var length by remember { mutableStateOf(24f) }
    var upper by remember { mutableStateOf(true) }
    var lower by remember { mutableStateOf(true) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    var generated by remember { mutableStateOf<dev.zpasswd.app.crypto.GeneratedPassword?>(null) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("长度：${length.toInt()}", style = MaterialTheme.typography.bodyMedium)
            Slider(
                value = length,
                onValueChange = { length = it },
                valueRange = 8f..64f,
                steps = 55,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = upper, onCheckedChange = { upper = it })
                Text("大写")
                Checkbox(checked = lower, onCheckedChange = { lower = it })
                Text("小写")
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = digits, onCheckedChange = { digits = it })
                Text("数字")
                Checkbox(checked = symbols, onCheckedChange = { symbols = it })
                Text("符号")
            }
            Spacer(Modifier.height(8.dp))
            val anyCharset = upper || lower || digits || symbols
            Button(
                onClick = {
                    generated = runCatching {
                        ZpCrypto.generatePassword(
                            length = length.toInt(),
                            uppercase = upper,
                            lowercase = lower,
                            digits = digits,
                            symbols = symbols,
                            excludeSimilar = true,
                        )
                    }.getOrNull()
                },
                enabled = anyCharset,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Filled.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("生成密码")
            }
            generated?.let { g ->
                Spacer(Modifier.height(12.dp))
                SelectionContainer {
                    Text(g.password, style = MaterialTheme.typography.bodyLarge, fontFamily = FontFamily.Monospace)
                }
                Spacer(Modifier.height(4.dp))
                val lowEntropy = g.entropyBits < 128
                Text(
                    "熵值：${"%.1f".format(g.entropyBits)} bits" +
                        if (lowEntropy) "（偏低，建议加长）" else "",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (lowEntropy) Color(0xFFB8860B)
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                    fontWeight = if (lowEntropy) FontWeight.Bold else FontWeight.Normal,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = { onUse(g.password) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("使用此密码") }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 5. 设置
// ---------------------------------------------------------------------------

@Composable
fun SettingsScreen(
    activity: FragmentActivity,
    repo: VaultRepository,
    onBack: () -> Unit,
    onWipeAll: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("设置") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            SyncSection(activity = activity, repo = repo)
            Spacer(Modifier.height(8.dp))
            IdleLockSection(repo = repo)
            Spacer(Modifier.height(8.dp))
            BackupSection(activity = activity, repo = repo)
            Spacer(Modifier.height(8.dp))
            RecoverySection(activity = activity, repo = repo)
            Spacer(Modifier.height(8.dp))
            BiometricSection(activity = activity, repo = repo)
            Spacer(Modifier.height(8.dp))
            ChangePasswordSection(activity = activity, repo = repo)
            Spacer(Modifier.height(8.dp))
            DangerSection(activity = activity, repo = repo, onWipeAll = onWipeAll)
            Spacer(Modifier.height(24.dp))
        }
    }
}

// ---- 同步 ----

@Composable
private fun SyncSection(activity: FragmentActivity, repo: VaultRepository) {
    val scope = rememberCoroutineScope()
    var syncState by remember { mutableStateOf<dev.zpasswd.app.data.SyncStateEntity?>(null) }
    var serverUrl by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var deviceName by remember { mutableStateOf(android.os.Build.MODEL ?: "Android") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var showConnectDialog by remember { mutableStateOf(false) }

    fun reload() {
        scope.launch(Dispatchers.IO) {
            val s = repo.getSyncState()
            withContext(Dispatchers.Main) {
                syncState = s
                if (s != null) {
                    serverUrl = s.serverUrl
                    email = s.email
                    deviceName = s.deviceName
                }
            }
        }
    }
    LaunchedEffect(Unit) { reload() }

    SectionTitle("同步")
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            if (syncState != null) {
                Text("已连接：${syncState!!.email}", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "服务器：${syncState!!.serverUrl}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            busy = true; message = null
                            scope.launch(Dispatchers.IO) {
                                try {
                                    val r = SyncEngine(repo).runSync()
                                    withContext(Dispatchers.Main) {
                                        message = "同步完成：推送 ${r.pushed}，拉取 ${r.pulled}" +
                                            if (r.conflicts > 0) "，冲突 ${r.conflicts}（已存入「同步冲突」）" else ""
                                    }
                                } catch (e: Exception) {
                                    withContext(Dispatchers.Main) { message = e.message ?: "同步失败" }
                                } finally {
                                    withContext(Dispatchers.Main) { busy = false }
                                }
                            }
                        },
                        enabled = !busy,
                        modifier = Modifier.weight(1f),
                    ) {
                        Icon(Icons.Filled.Sync, contentDescription = null)
                        Spacer(Modifier.width(4.dp))
                        Text("立即同步")
                    }
                    OutlinedButton(
                        onClick = {
                            scope.launch(Dispatchers.IO) {
                                SyncEngine(repo).disconnect()
                                withContext(Dispatchers.Main) { reload() }
                            }
                        },
                        enabled = !busy,
                        modifier = Modifier.weight(1f),
                    ) { Text("断开") }
                }
            } else {
                OutlinedTextField(value = serverUrl, onValueChange = { serverUrl = it },
                    label = { Text("服务器地址") }, placeholder = { Text("https://…") },
                    modifier = Modifier.fillMaxWidth(), singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(value = email, onValueChange = { email = it },
                    label = { Text("邮箱") }, modifier = Modifier.fillMaxWidth(), singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email))
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(value = deviceName, onValueChange = { deviceName = it },
                    label = { Text("设备名") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick = { showConnectDialog = true },
                    enabled = serverUrl.isNotBlank() && email.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("连接同步") }
            }
            message?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    // 连接同步：二次输入主密码
    if (showConnectDialog) {
        var masterPw by remember { mutableStateOf("") }
        var dlgError by remember { mutableStateOf<String?>(null) }
        var dlgBusy by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { if (!dlgBusy) showConnectDialog = false },
            title = { Text("连接同步服务") },
            text = {
                Column {
                    Text("请输入主密码以完成连接。")
                    Spacer(Modifier.height(8.dp))
                    PasswordField(value = masterPw, onValueChange = { masterPw = it }, label = "主密码")
                    ErrorText(dlgError)
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        dlgBusy = true; dlgError = null
                        val url = serverUrl; val em = email; val dn = deviceName
                        scope.launch(Dispatchers.IO) {
                            try {
                                SyncEngine(repo).connectSync(url, em, dn, masterPw)
                                withContext(Dispatchers.Main) {
                                    showConnectDialog = false
                                    message = "连接成功"
                                    reload()
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    dlgError = e.message ?: "连接失败"
                                    dlgBusy = false
                                }
                            }
                        }
                    },
                    enabled = !dlgBusy && masterPw.isNotEmpty(),
                ) { Text("连接") }
            },
            dismissButton = {
                TextButton(onClick = { showConnectDialog = false }, enabled = !dlgBusy) { Text("取消") }
            },
        )
    }
}

// ---- 空闲锁定 ----

@Composable
private fun IdleLockSection(repo: VaultRepository) {
    val scope = rememberCoroutineScope()
    var idleText by remember { mutableStateOf("5") }
    var saved by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val v = withContext(Dispatchers.IO) { repo.db.metaDao().get(VaultRepository.KEY_IDLE_MINUTES) }
        if (v != null) idleText = v
    }

    SectionTitle("空闲锁定")
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = idleText,
                onValueChange = { if (it.all { c -> c.isDigit() } && it.length <= 4) idleText = it },
                label = { Text("分钟数") },
                modifier = Modifier.weight(1f),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = {
                    val minutes = idleText.toIntOrNull()
                    if (minutes == null || minutes < 1 || minutes > 1440) {
                        idleText = "5"
                    }
                    val final = idleText.toIntOrNull()?.coerceIn(1, 1440) ?: 5
                    idleText = final.toString()
                    scope.launch(Dispatchers.IO) {
                        repo.db.metaDao().put(MetaEntity(VaultRepository.KEY_IDLE_MINUTES, final.toString()))
                        withContext(Dispatchers.Main) { saved = true }
                    }
                },
            ) { Text("保存") }
        }
        if (saved) {
            Text(
                "已保存：切后台超过该分钟数后自动锁定",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp).padding(bottom = 12.dp),
            )
        }
    }
}

// ---- 导出备份 ----

@Composable
private fun BackupSection(activity: FragmentActivity, repo: VaultRepository) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }

    SectionTitle("备份")
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "导出加密备份（JSON，条目为密文，需主密码/恢复码恢复）。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    busy = true
                    scope.launch(Dispatchers.IO) {
                        try {
                            val backup = repo.exportBackup()
                            val json = Json.encodeToString(backup)
                            val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                            val dir = activity.getExternalFilesDir(null)
                                ?: throw IllegalStateException("无法访问外部存储目录")
                            val file = java.io.File(dir, "zpasswd-backup-$stamp.json")
                            file.writeText(json, Charsets.UTF_8)
                            withContext(Dispatchers.Main) {
                                toast(activity, "已导出：${file.absolutePath}")
                            }
                        } catch (e: Exception) {
                            withContext(Dispatchers.Main) {
                                toast(activity, "导出失败：${e.message}")
                            }
                        } finally {
                            withContext(Dispatchers.Main) { busy = false }
                        }
                    }
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                else Icon(Icons.Filled.Download, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(if (busy) "导出中…" else "导出加密备份")
            }
        }
    }
}

// ---- 恢复码 ----

@Composable
private fun RecoverySection(activity: FragmentActivity, repo: VaultRepository) {
    val scope = rememberCoroutineScope()
    var showVerify by remember { mutableStateOf(false) }
    var words by remember { mutableStateOf<String?>(null) }

    SectionTitle("恢复码")
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "24 词恢复码可在忘记主密码时恢复数据，请抄写在纸上妥善保管。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { showVerify = true },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("查看恢复码") }
            words?.let {
                Spacer(Modifier.height(12.dp))
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)) {
                    SelectionContainer {
                        Text(
                            it.split(" ").mapIndexed { i, w -> "${i + 1}. $w" }.joinToString("  "),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                }
            }
        }
    }

    if (showVerify) {
        var masterPw by remember { mutableStateOf("") }
        var dlgError by remember { mutableStateOf<String?>(null) }
        var dlgBusy by remember { mutableStateOf(false) }
        AlertDialog(
            onDismissRequest = { if (!dlgBusy) showVerify = false },
            title = { Text("验证主密码") },
            text = {
                Column {
                    Text("查看恢复码前请先验证主密码。")
                    Spacer(Modifier.height(8.dp))
                    PasswordField(value = masterPw, onValueChange = { masterPw = it }, label = "主密码")
                    ErrorText(dlgError)
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        dlgBusy = true; dlgError = null
                        scope.launch(Dispatchers.IO) {
                            try {
                                repo.unlock(masterPw) // 主密码错误抛异常
                                val saltB64 = repo.getSaltB64()
                                    ?: throw IllegalStateException("vault 数据损坏")
                                val mk = ZpCrypto.deriveMasterKey(masterPw, ZpCrypto.b64decode(saltB64))
                                val mnemonic = try {
                                    RecoveryCode.fromMasterKey(mk)
                                } finally {
                                    ZpCrypto.wipe(mk)
                                }
                                withContext(Dispatchers.Main) {
                                    words = mnemonic
                                    showVerify = false
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    dlgError = "主密码不正确"
                                    dlgBusy = false
                                }
                            }
                        }
                    },
                    enabled = !dlgBusy && masterPw.isNotEmpty(),
                ) { Text("验证") }
            },
            dismissButton = {
                TextButton(onClick = { showVerify = false }, enabled = !dlgBusy) { Text("取消") }
            },
        )
    }
}

// ---- 指纹解锁 ----

@Composable
private fun BiometricSection(activity: FragmentActivity, repo: VaultRepository) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val available = remember { BiometricUnlock.isAvailable(context) }
    var enrolled by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        enrolled = withContext(Dispatchers.IO) { BiometricUnlock.isEnrolled(repo) }
    }

    SectionTitle("指纹解锁")
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("指纹快捷解锁", style = MaterialTheme.typography.bodyLarge)
                Text(
                    if (!available) "此设备不支持生物识别"
                    else "开启后可用指纹快速解锁",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = enrolled,
                enabled = available && !busy,
                onCheckedChange = { want ->
                    busy = true
                    if (want) {
                        BiometricUnlock.enroll(
                            activity, repo,
                            onDone = {
                                enrolled = true; busy = false
                                toast(activity, "指纹解锁已开启")
                            },
                            onError = { msg ->
                                busy = false
                                toast(activity, "开启失败：$msg")
                            },
                        )
                    } else {
                        scope.launch(Dispatchers.IO) {
                            BiometricUnlock.clear(repo)
                            withContext(Dispatchers.Main) {
                                enrolled = false; busy = false
                                toast(activity, "指纹解锁已关闭")
                            }
                        }
                    }
                },
            )
        }
    }
}

// ---- 修改主密码 ----

@Composable
private fun ChangePasswordSection(activity: FragmentActivity, repo: VaultRepository) {
    val scope = rememberCoroutineScope()
    var oldPw by remember { mutableStateOf("") }
    var newPw1 by remember { mutableStateOf("") }
    var newPw2 by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var isError by remember { mutableStateOf(false) }

    SectionTitle("修改主密码")
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            PasswordField(value = oldPw, onValueChange = { oldPw = it }, label = "旧主密码")
            Spacer(Modifier.height(8.dp))
            PasswordField(value = newPw1, onValueChange = { newPw1 = it }, label = "新主密码（至少 12 位）")
            Spacer(Modifier.height(8.dp))
            PasswordField(value = newPw2, onValueChange = { newPw2 = it }, label = "再次输入新主密码")
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = {
                    when {
                        newPw1.length < 12 -> { message = "新主密码至少 12 位"; isError = true; return@Button }
                        newPw1 != newPw2 -> { message = "两次输入不一致"; isError = true; return@Button }
                    }
                    busy = true; message = null
                    scope.launch(Dispatchers.IO) {
                        try {
                            repo.changePassword(oldPw, newPw1)
                            withContext(Dispatchers.Main) {
                                message = "主密码已修改"
                                isError = false
                                oldPw = ""; newPw1 = ""; newPw2 = ""
                            }
                        } catch (e: Exception) {
                            withContext(Dispatchers.Main) {
                                message = e.message ?: "修改失败"
                                isError = true
                            }
                        } finally {
                            withContext(Dispatchers.Main) { busy = false }
                        }
                    }
                },
                enabled = !busy && oldPw.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (busy) CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                else Text(if (busy) "修改中…" else "修改主密码")
            }
            message?.let {
                Spacer(Modifier.height(8.dp))
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (isError) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

// ---- 危险区 ----

@Composable
private fun DangerSection(activity: FragmentActivity, repo: VaultRepository, onWipeAll: () -> Unit) {
    val scope = rememberCoroutineScope()
    var showConfirm by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }

    SectionTitle("危险区")
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                "清除所有本地数据（条目、主密码、同步配置），不可恢复。请先导出备份。",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { showConfirm = true },
                enabled = !busy,
                colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) { Text("清除所有数据") }
        }
    }

    if (showConfirm) {
        var confirmText by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { if (!busy) showConfirm = false },
            title = { Text("清除所有数据") },
            text = {
                Column {
                    Text("此操作不可恢复。请输入「删除」以确认：")
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = confirmText,
                        onValueChange = { confirmText = it },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        busy = true
                        scope.launch(Dispatchers.IO) {
                            try {
                                repo.wipeAll()
                                withContext(Dispatchers.Main) { onWipeAll() }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    busy = false
                                    toast(activity, "清除失败：${e.message}")
                                }
                            }
                        }
                    },
                    enabled = !busy && confirmText.trim() == "删除",
                ) { Text("确认清除", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showConfirm = false }, enabled = !busy) { Text("取消") }
            },
        )
    }
}
