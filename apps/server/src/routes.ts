/**
 * API 路由。全部 JSON，base path /v1。
 *
 * 铁律：
 * - 服务端永远不接触明文、主密码、MK；收到的 nonce/ciphertext 都是不透明字符串。
 * - **时间一律以服务端为准**：vault_items.updated_at / deleted_at 由服务端盖章，
 *   客户端传来的 updatedAt 只用于它本地的展示与排序，不入库；增量同步游标同样取
 *   服务端时钟。两者同源，客户端时钟偏差不会再造成漏拉。
 * - 错误信息不区分"用户不存在 / 密码错误"（登录统一 invalid credentials；
 *   注册时邮箱冲突伪装成成功）。
 * - 日志只打 userId，不打 email（本服务默认不打业务日志）。
 */
import type { App } from './auth';
import {
  getDummyVerifier,
  loginRateLimited,
  requireAuth,
  signAccessToken,
  signRefreshToken,
  verifyAuthKey,
  verifyRefreshToken,
} from './auth';
import { getUserByEmail, getUserById, toItemJson } from './db';
import type { VaultItemRow } from './db';

function isValidEmail(s: unknown): s is string {
  return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 254;
}

/**
 * 增量同步游标的安全回溯窗口（毫秒）。
 *
 * 写入与拉取是并发的两条路径：写入方在 T1 取样时间戳、T2 才真正提交；拉取方若在
 * T1..T2 之间取样游标并查询，就会发出一个"比该行更新的游标"，该行此后永远满足不了
 * `updated_at >= since`，被永久漏拉（对密码管理器来说就是丢数据）。
 *
 * 让游标保守地退后几秒即可消除这个窗口：这段时间内的变更会被重复投递，客户端按
 * version 幂等处理（version 不大于本地就跳过），代价可忽略。
 */
const SYNC_CURSOR_LOOKBACK_MS = 5_000;

async function readJson(c: { req: { json(): Promise<unknown> } }): Promise<Record<string, unknown> | null> {
  try {
    const b = await c.req.json();
    return b && typeof b === 'object' ? (b as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function registerRoutes(app: App) {
  // ------------------------------------------------------------ 注册 ----
  app.post('/v1/auth/signup', async (c) => {
    const body = await readJson(c);
    const email = body?.email;
    // 扩展端发 kdfSalt；kdfSaltB64 保留做兼容
    const kdfSalt = typeof body?.kdfSalt === 'string' ? body.kdfSalt : body?.kdfSaltB64;
    const authVerifier = body?.authVerifier;
    const wrappedDek = body?.wrappedDek as { nonce?: unknown; ciphertext?: unknown } | undefined;
    // recoveryVerifier 可选：核心恢复流程（24 词 → recKey → authKey 登录）不需要它
    const recoveryVerifier = typeof body?.recoveryVerifier === 'string' ? body.recoveryVerifier : null;
    if (
      !isValidEmail(email) ||
      typeof kdfSalt !== 'string' ||
      typeof authVerifier !== 'string' ||
      typeof wrappedDek?.nonce !== 'string' ||
      typeof wrappedDek?.ciphertext !== 'string'
    ) {
      return c.json({ error: 'invalid request' }, 400);
    }

    const id = crypto.randomUUID();
    try {
      await c.env.DB.prepare(
        `INSERT INTO users (id, email, kdf_salt, auth_verifier, wrapped_dek_nonce, wrapped_dek_ct, recovery_verifier, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          id,
          email.toLowerCase(),
          kdfSalt,
          authVerifier,
          wrappedDek.nonce,
          wrappedDek.ciphertext,
          recoveryVerifier,
          Date.now(),
        )
        .run();
    } catch (e) {
      // 邮箱已被注册：伪装成成功返回，攻击者无法用注册接口枚举账号是否存在。
      // 注意：真正的 DB 故障也会被伪装，部署后如注册普遍"成功但登不上"请查 D1 日志。
      if (e instanceof Error && /UNIQUE/i.test(e.message)) return c.json({ ok: true }, 200);
      return c.json({ error: 'internal error' }, 500);
    }
    return c.json({ ok: true }, 201);
  });

  // ------------------------------------------------------------ 登录 ----
  app.post('/v1/auth/login', async (c) => {
    const body = await readJson(c);
    const email = typeof body?.email === 'string' ? body.email.toLowerCase() : '';
    const authKeyB64 = body?.authKeyB64;
    const ip = c.req.header('cf-connecting-ip') ?? 'unknown';
    // 参数缺失与凭证错误返回同一错误体，不泄露哪一环出了问题
    if (!isValidEmail(email) || typeof authKeyB64 !== 'string') {
      return c.json({ error: 'invalid credentials' }, 401);
    }
    if (loginRateLimited(ip, email)) {
      return c.json({ error: 'too many attempts, try later' }, 429);
    }
    const user = await getUserByEmail(c.env.DB, email);
    // 用户不存在时用假验签跑一次 SHA-256，让两种失败路径耗时不可区分
    const verifier = user ? user.auth_verifier : await getDummyVerifier();
    const ok = await verifyAuthKey(authKeyB64, verifier);
    if (!user || !ok) return c.json({ error: 'invalid credentials' }, 401);

    const accessJwt = await signAccessToken(c.env, user.id);
    const { token: refreshJwt } = await signRefreshToken(c.env, user.id);
    return c.json({ accessJwt, refreshJwt });
  });

  // ------------------------------------------ 取 KDF 参数（新设备从同步恢复用） ----
  // 公开接口：salt 与 wrappedDek 不是秘密（没有主密码谁也解不开）。
  // 不存在的邮箱返回 404，客户端据此提示"该邮箱没有同步账号"。
  app.get('/v1/auth/salt', async (c) => {
    const email = (c.req.query('email') ?? '').toLowerCase();
    if (!isValidEmail(email)) return c.json({ error: 'invalid request' }, 400);
    const user = await getUserByEmail(c.env.DB, email);
    if (!user) return c.json({ error: 'not found' }, 404);
    return c.json({
      kdfSalt: user.kdf_salt,
      wrappedDek: { nonce: user.wrapped_dek_nonce, ciphertext: user.wrapped_dek_ct },
    });
  });

  // ------------------------------------------------------ refresh ----
  app.post('/v1/auth/refresh', async (c) => {
    const body = await readJson(c);
    const token = body?.refreshJwt;
    if (typeof token !== 'string') return c.json({ error: 'invalid token' }, 401);
    const payload = await verifyRefreshToken(c.env, token);
    if (!payload) return c.json({ error: 'invalid token' }, 401);

    const revoked = await c.env.DB.prepare('SELECT 1 FROM refresh_revoked WHERE jti = ?')
      .bind(payload.jti)
      .first();
    if (revoked) return c.json({ error: 'invalid token' }, 401);

    // rotation：签发新 pair，旧 jti 写入吊销表（复用即失效，防 token 盗用重放）
    const db = c.env.DB;
    await db.batch([
      db.prepare('INSERT OR IGNORE INTO refresh_revoked (jti, expires_at) VALUES (?, ?)').bind(
        payload.jti,
        payload.exp * 1000,
      ),
      db.prepare('DELETE FROM refresh_revoked WHERE expires_at < ?').bind(Date.now()),
    ]);
    const accessJwt = await signAccessToken(c.env, payload.sub);
    const { token: refreshJwt } = await signRefreshToken(c.env, payload.sub);
    return c.json({ accessJwt, refreshJwt });
  });

  // ------------------------------------------------------ 换密码 ----
  app.post('/v1/auth/change-password', requireAuth, async (c) => {
    const userId = c.get('userId');
    const body = await readJson(c);
    const newAuthVerifier = body?.newAuthVerifier;
    const newWrappedDek = body?.newWrappedDek as { nonce?: unknown; ciphertext?: unknown } | undefined;
    const newRecoveryVerifier = body?.newRecoveryVerifier;
    if (
      typeof newAuthVerifier !== 'string' ||
      typeof newWrappedDek?.nonce !== 'string' ||
      typeof newWrappedDek?.ciphertext !== 'string' ||
      typeof newRecoveryVerifier !== 'string'
    ) {
      return c.json({ error: 'invalid request' }, 400);
    }
    await c.env.DB.prepare(
      `UPDATE users SET auth_verifier = ?, wrapped_dek_nonce = ?, wrapped_dek_ct = ?, recovery_verifier = ?
       WHERE id = ?`,
    )
      .bind(newAuthVerifier, newWrappedDek.nonce, newWrappedDek.ciphertext, newRecoveryVerifier, userId)
      .run();
    // 已知局限：此前签发的 refresh token 在到期前（最长 30 天）仍然有效。
    // 如需换密码即失效全部会话，需给 refresh_revoked 加 user_id 列并在此批量吊销 —— 列为加固项。
    return c.json({ ok: true });
  });

  // ------------------------------------------------------ 增量同步 ----
  app.get('/v1/sync', requireAuth, async (c) => {
    const userId = c.get('userId');
    const q = c.req.query('since');
    // since 为 ISO 字符串（扩展端）或毫秒数；解析失败则全量
    let since = 0;
    if (typeof q === 'string' && q.length > 0) {
      const t = /^\d+$/.test(q) ? Number(q) : Date.parse(q);
      if (Number.isFinite(t) && t > 0) since = t;
    }
    // 游标与 updated_at 同源（都是服务端时钟），并做两点保证：
    // 1) 取样放在查询之前，且比较用 >=：恰好在边界毫秒上写入的行不会被漏掉
    //    （最坏只是重复投递一次，客户端按 version 幂等）；
    // 2) 返回的游标再退 SYNC_CURSOR_LOOKBACK_MS，覆盖"写入方已取样时间戳、
    //    但行尚未提交"的并发窗口。
    const nowMs = Date.now();
    const rows = await c.env.DB.prepare(
      `SELECT id, user_id, nonce, ciphertext, version, folder_id, favorite, updated_at, deleted_at
       FROM vault_items WHERE user_id = ? AND updated_at >= ? ORDER BY updated_at ASC`,
    )
      .bind(userId, since)
      .all<VaultItemRow>();
    return c.json({
      items: (rows.results ?? []).map(toItemJson),
      serverTime: new Date(nowMs - SYNC_CURSOR_LOOKBACK_MS).toISOString(),
    });
  });

  // ---------------------------------------------- 批量上传（乐观锁）----
  // 注：Google 风格的 `/v1/items:batch` 在 Hono 里会被解析成路由参数，
  // 故用 `/v1/items/batch`，语义相同。
  app.put('/v1/items/batch', requireAuth, async (c) => {
    const userId = c.get('userId');
    const body = await readJson(c);
    const items = Array.isArray(body) ? body : (body as { items?: unknown } | null)?.items;
    if (!Array.isArray(items)) return c.json({ error: 'invalid request' }, 400);

    const ids = items.filter((i) => i && typeof (i as { id?: unknown }).id === 'string').map((i) => (i as { id: string }).id);
    const serverVersions = new Map<string, number>();
    if (ids.length > 0) {
      const placeholders = ids.map(() => '?').join(',');
      const existing = await c.env.DB.prepare(
        `SELECT id, version FROM vault_items WHERE user_id = ? AND id IN (${placeholders})`,
      )
        .bind(userId, ...ids)
        .all<{ id: string; version: number }>();
      for (const r of existing.results ?? []) serverVersions.set(r.id, r.version);
    }

    const accepted: string[] = [];
    const rejectedIds: string[] = [];
    const stmts: D1PreparedStatement[] = [];
    // 时间一律以服务端为准：客户端传来的 updatedAt 只用于它本地的展示与排序，**不入库**。
    // 若采信客户端时钟，时钟慢的设备写入的行会"落在游标的过去"（游标是服务端时钟），
    // 其他设备将永久漏拉。取样点放在构造语句前，尽量贴近真正写入的时刻。
    const now = Date.now();
    for (const raw of items) {
      const it = raw as {
        id?: unknown;
        nonce?: unknown;
        ciphertext?: unknown;
        version?: unknown;
        folderId?: unknown;
        favorite?: unknown;
        /** 客户端本地时间，服务端刻意忽略（见上方注释） */
        updatedAt?: unknown;
        deletedAt?: unknown;
      };
      // 畸形条目直接跳过（不进 accepted/rejected，避免客户端死循环重试）
      if (
        typeof it?.id !== 'string' ||
        typeof it?.nonce !== 'string' ||
        typeof it?.ciphertext !== 'string' ||
        !Number.isInteger(it?.version)
      ) {
        continue;
      }
      const sv = serverVersions.get(it.id);
      if (sv !== undefined && (it.version as number) <= sv) {
        rejectedIds.push(it.id);
        continue;
      }
      accepted.push(it.id);
      const updatedAt = now;
      // 客户端只表达"删了"，不表达"何时删的"：deleted_at 同样用服务端收到删除的时刻
      const deletedAt = it.deletedAt == null ? null : now;
      stmts.push(
        c.env.DB.prepare(
          `INSERT INTO vault_items (id, user_id, nonce, ciphertext, version, folder_id, favorite, updated_at, deleted_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(user_id, id) DO UPDATE SET
             nonce = excluded.nonce, ciphertext = excluded.ciphertext, version = excluded.version,
             folder_id = excluded.folder_id, favorite = excluded.favorite,
             updated_at = excluded.updated_at, deleted_at = excluded.deleted_at`,
        ).bind(
          it.id,
          userId,
          it.nonce,
          it.ciphertext,
          it.version as number,
          typeof it.folderId === 'string' ? it.folderId : null,
          it.favorite === true ? 1 : 0,
          updatedAt,
          deletedAt,
        ),
      );
    }
    if (stmts.length > 0) await c.env.DB.batch(stmts);
    // 被拒绝的条目带回服务端完整版本，供客户端做冲突处理
    const rejected: { id: string; item: ReturnType<typeof toItemJson> }[] = [];
    if (rejectedIds.length > 0) {
      const placeholders = rejectedIds.map(() => '?').join(',');
      const rows = await c.env.DB.prepare(
        `SELECT id, user_id, nonce, ciphertext, version, folder_id, favorite, updated_at, deleted_at
         FROM vault_items WHERE user_id = ? AND id IN (${placeholders})`,
      )
        .bind(userId, ...rejectedIds)
        .all<VaultItemRow>();
      for (const r of rows.results ?? []) rejected.push({ id: r.id, item: toItemJson(r) });
    }
    return c.json({ accepted, rejected });
  });

  // ------------------------------------------------------ 加密导出 ----
  app.get('/v1/export', requireAuth, async (c) => {
    const userId = c.get('userId');
    const user = await getUserById(c.env.DB, userId);
    if (!user) return c.json({ error: 'unauthorized' }, 401);
    const rows = await c.env.DB.prepare(
      `SELECT id, user_id, nonce, ciphertext, version, folder_id, favorite, updated_at, deleted_at
       FROM vault_items WHERE user_id = ? AND deleted_at IS NULL ORDER BY updated_at ASC`,
    )
      .bind(userId)
      .all<VaultItemRow>();
    return c.json({
      kdfSalt: user.kdf_salt,
      wrappedDek: { nonce: user.wrapped_dek_nonce, ciphertext: user.wrapped_dek_ct },
      items: (rows.results ?? []).map(toItemJson),
      exportedAt: Date.now(),
    });
  });

  // ------------------------------------------------------------ 设备 ----
  app.post('/v1/devices', requireAuth, async (c) => {
    const userId = c.get('userId');
    const body = await readJson(c);
    if (typeof body?.pubkey !== 'string' || typeof body?.name !== 'string' || body.name.length > 100) {
      return c.json({ error: 'invalid request' }, 400);
    }
    const id = crypto.randomUUID();
    await c.env.DB.prepare(`INSERT INTO devices (id, user_id, pubkey, name, created_at) VALUES (?, ?, ?, ?, ?)`)
      .bind(id, userId, body.pubkey, body.name, Date.now())
      .run();
    return c.json({ deviceId: id }, 201);
  });

  app.get('/v1/devices', requireAuth, async (c) => {
    const userId = c.get('userId');
    const rows = await c.env.DB.prepare(
      `SELECT id, name, created_at, revoked_at FROM devices WHERE user_id = ? ORDER BY created_at ASC`,
    )
      .bind(userId)
      .all<{ id: string; name: string; created_at: number; revoked_at: number | null }>();
    return c.json({
      devices: (rows.results ?? []).map((d) => ({
        id: d.id,
        name: d.name,
        createdAt: d.created_at,
        revokedAt: d.revoked_at,
      })),
    });
  });

  app.delete('/v1/devices/:id', requireAuth, async (c) => {
    const userId = c.get('userId');
    const id = c.req.param('id');
    await c.env.DB.prepare(`UPDATE devices SET revoked_at = ? WHERE id = ? AND user_id = ?`)
      .bind(Date.now(), id, userId)
      .run();
    // 即使 id 不存在也返回 ok，不泄露设备是否存在
    return c.json({ ok: true });
  });
}
