# password-manager

自研零知识密码生成与管理工具。

- **范围**：浏览器扩展（Manifest V3）+ 可选的 Node.js 同步服务，全 TS 栈
- **安全模型**：零知识。主密码经 Argon2id 派生主密钥，所有条目在客户端用 XChaCha20-Poly1305 加密；服务端只存密文。登录凭证与解密密钥经不同 KDF context 派生，拖库也解不开。
- 技术方案：`~/workspace/your_files/password-manager-tech-design.md`

## 结构

```
packages/crypto/   # 共享密码学核心：KDF / 信封加密 / AEAD / 密码生成器 / 恢复码
apps/extension/    # 浏览器扩展（MV3）：popup / options / content-script / background
apps/server/       # 同步服务（Cloudflare Workers + Hono + D1），"哑管道"只存密文
apps/android/      # Android 原生 App（Kotlin+Compose）：AutofillService / 指纹解锁 / 同步
```

## 开发

```bash
pnpm install
pnpm --filter @pm/crypto test     # crypto 包测试（必须全绿）
pnpm --filter @pm/extension dev   # 扩展开发模式
pnpm --filter @pm/server dev      # 同步服务开发模式
```

## 安全纪律

- 不手写密码学原语，只用 libsodium / bip39
- `packages/crypto` 的 KDF 参数是冻结的，任何修改必须同步更新扩展与服务端并经人工 review
- 私钥/主密码/恢复码永不进 git，永不进聊天记录
