# zpasswd Android App

zpasswd 的原生 Android 客户端（Kotlin + Jetpack Compose），与浏览器扩展共享同一个零知识 vault、连接同一个同步服务。

- 包名：`dev.zpasswd.app`，应用名 `zpasswd`
- minSdk 26（Autofill 要求），targetSdk 34
- 密码学：`com.goterl:lazysodium-android:5.2.0`（JNI libsodium），与 `@pm/crypto` 字节级兼容（见下）

## 功能

- **解锁**：主密码 → Argon2id（opslimit=3, memlimit=64MB，手机上约 1–2 秒）→ MK 只驻内存；另支持**指纹快捷解锁**（Android Keystore AES 密钥加密 DEK，指纹验证经 `BiometricPrompt.CryptoObject` 原子绑定）
- **密码库**：搜索/查看/新建/编辑/删除，密码 30 秒自动清除剪贴板，TOTP 实时码
- **密码生成器**：CSPRNG + 拒绝采样，与扩展端字符集逐字符一致，显示熵值（<128bit 警告）
- **AutofillService**：系统级自动填充。解析 `AssistStructure` 找密码框，按 eTLD+1（网页）/包名（App）匹配条目；vault 锁定时走认证 Intent 跳解锁页；API 30+ 用 inline suggestions，低版本用下拉 dataset；`onSaveRequest` 收集新凭证回 App 内确认保存
- **同步**：与扩展端 `sync.ts` 同逻辑——`GET /v1/sync?since=` 增量拉取、`PUT /v1/items/batch` 推送（version 乐观锁）、401 自动 refresh、登录→401→注册→再登录、冲突副本进「同步冲突」文件夹
- **设置**：同步服务器 URL/邮箱/设备名、空闲锁定、加密备份导出（与扩展端 `zpasswd-export-v1` 格式兼容）、恢复码（BIP39 24 词，需主密码二次验证）、换主密码、清除数据
- **安全铁律**：明文密码/主密码/MK/DEK 永不落盘；落盘只有密文、salt、wrappedDek、JWT；锁定时内存密钥清零；`allowBackup=false`

## 构建

需要 JDK 17+、Android SDK（platform 34、build-tools 34.0.0）。

```bash
cd apps/android
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

JVM 单元测试（含字节级兼容向量）：

```bash
./gradlew :app:testDebugUnitTest
```

## 密码学兼容性

`CryptoCompatTest`（`app/src/test/java/.../crypto/CryptoCompatTest.kt`）断言
`packages/crypto/test/vectors.json` 的全部确定性向量：

- KDF 参数冻结（Argon2id, opslimit=3, memlimit=64MiB）
- `deriveMasterKey` / 三个子密钥（enc/auth/rec）逐字节一致
- XChaCha20-Poly1305 固定 nonce 向量密文一致 + 解密回环
- `authVerifier = base64(SHA-256(authKey))` 一致
- wrap/unwrap、encrypt/decrypt 回环 + 篡改检测
- 生成器字符集与 `generator.ts` 逐字符一致（81 字符；TS 注释里的"80"是笔误）
- BIP39 24 词回环、TOTP RFC 6238 向量

> 注意：`com.goterl:lazysodium-android` 的正确 Maven 坐标是
> `com.goterl:lazysodium-android:5.2.0`（groupId 无 `-lazy-sodium-android` 后缀）。

## 真机验证步骤

1. 安装 APK（`adb install app-debug.apk`），打开 App，创建 vault（主密码 ≥12 位）
2. 新建一条目（含 TOTP 种子），确认列表/详情/复制/TOTP 码正常
3. **Autofill**：系统设置 → 语言和输入法 → 自动填充服务 → 选 zpasswd；
   打开任意 App 的登录页，点密码框 → 应弹出 vault 匹配项 → 指纹验证 → 自动填充
4. **锁定态填充**：锁定 vault 后重复步骤 3 → 应先跳解锁页，解锁后继续填充
5. **同步**：设置页填 `https://zpasswd-server.favlink.workers.dev`、邮箱、设备名，
   点"连接同步"（会走登录→401→注册→再登录）→ 新建条目 → 立即同步 →
   在桌面扩展上同步，应看到同一条目（反之亦然）
6. **指纹**：设置页开启指纹解锁 → 锁定 → 点指纹按钮 → 应直接解锁
7. **恢复码**：设置页查看恢复码（需主密码），抄下 24 词；在扩展端应能用同一恢复码恢复（rec 子密钥一致）

## 已知限制

- 本仓库沙箱环境因 Gradle daemon 的 localhost IPC 被拦截，`./gradlew` 无法在本机跑通；
  密码学兼容性已用 `kotlinc` + `lazysodium-java` 在 JVM 上逐项验证全绿（16/16）。
  在正常机器/CI 上 `./gradlew assembleDebug` 与 `:app:testDebugUnitTest` 应直接通过。
- `change-password` 暂未吊销已有 refresh token（与服务端 TODO 一致，需服务端加 `user_id` 列）。
