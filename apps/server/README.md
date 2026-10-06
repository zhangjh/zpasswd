# @pm/server — zpasswd 同步服务

Cloudflare Workers + Hono + D1（SQLite）。**哑管道**：只做身份校验与密文存取，
永远不接触明文、主密码、主密钥。唯一的密码学操作是登录时的 argon2id 验签
（hash-wasm，Workers 原生 WASM）。

## 互通约定

- 客户端用 libsodium `crypto_pwhash_str` 对 **base64(ORIGINAL) 编码的 32 字节
  authKey** 生成 `$argon2id$v=19$...` PHC 字符串，作为 `authVerifier` 上传；
- 服务端 `argon2Verify({ password: authKeyB64, hash: verifier })` 校验。
  `password` 必须是完全相同的字符串（已实测互通）。

## 本地开发

```bash
pnpm install                      # 在仓库根目录执行一次
pnpm --filter @pm/server build    # tsc 类型检查，必须通过

# 本地 D1（无需 Cloudflare 账号）
pnpm --filter @pm/server db:migrate:local
echo 'JWT_SECRET="dev-secret-change-me"' > apps/server/.dev.vars   # 仅本地，不进 git
pnpm --filter @pm/server dev      # http://127.0.0.1:8787
```

## 首次部署（一把梭）

```bash
cd apps/server
wrangler d1 create zpasswd
# 把输出的 database_id 回填到 wrangler.toml 的 database_id 字段
wrangler d1 migrations apply zpasswd --remote
wrangler secret put JWT_SECRET    # 粘贴一个 32+ 字节随机字符串
wrangler deploy
```

`.dev.vars` 已在建议的 `.gitignore` 中（见仓库根 README），不要提交。

## API（base path /v1，全部 JSON）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/auth/signup` | `{email, kdfSaltB64, authVerifier, wrappedDek:{nonce,ciphertext}, recoveryVerifier}` → 201 `{ok:true}`。邮箱冲突时**伪装成 200 成功**，防账号枚举 |
| POST | `/v1/auth/login` | `{email, authKeyB64}` → `{accessJwt(15min), refreshJwt(30d)}`。失败统一 401 `{error:"invalid credentials"}`，不区分用户不存在/密码错；(IP+email) 滑动窗口限流 10 次/分钟 |
| POST | `/v1/auth/refresh` | `{refreshJwt}` → 新 pair，旧 jti 吊销（rotation，复用即失效） |
| POST | `/v1/auth/change-password` 🔒 | `{newAuthVerifier, newWrappedDek, newRecoveryVerifier}` |
| GET | `/v1/sync?since=` 🔒 | 增量拉取 `updatedAt > since` 的条目 → `{items, serverTime}` |
| PUT | `/v1/items/batch` 🔒 | 批量上传，version 乐观锁 → `{accepted:[ids], rejected:[{id, serverVersion}]}`。注：Google 风格的 `items:batch` 在 Hono 会被解析成路由参数，故用 `/items/batch` |
| GET | `/v1/export` 🔒 | 全量未删除密文 + kdfSalt + wrappedDek（加密快照） |
| POST | `/v1/devices` 🔒 | `{pubkey, name}` → `{deviceId}` |
| GET | `/v1/devices` 🔒 | 设备列表 |
| DELETE | `/v1/devices/:id` 🔒 | 软吊销（`revoked_at`），不存在也返回 ok |

🔒 = 需要 `Authorization: Bearer <accessJwt>`。

## 安全说明

- 错误信息不区分用户不存在/密码错误；用户不存在时服务端会跑一次同等量级的
  argon2id（假验签），让两种失败路径耗时不可区分。
- 登录限流是按 isolate 的内存 Map，Workers 多实例下为近似限流（已在代码注释）。
- 已知局限：换密码后，此前签发的 refresh token 在到期前（最长 30 天）仍有效。
  如需"换密码即踢掉所有会话"，给 `refresh_revoked` 加 `user_id` 列并在
  change-password 里批量吊销（加固项，未做）。
- 生产环境 `JWT_SECRET` 必须用 `wrangler secret put` 设置，长度 ≥ 32 字节随机。
