import { decryptItem, deriveSubkey, encryptItem, makeAuthVerifier } from '@pm/crypto';
import { getDb, getSyncState, saveSyncState, type SyncState } from './db';
import { CONFLICT_FOLDER_ID, CONFLICT_FOLDER_NAME, type StoredItem, type VaultItemPlain } from './types';
import { b64encode } from './util';

/** 默认同步服务器（Cloudflare Workers 官方后端）；用户可在设置中改为自建地址 */
export const DEFAULT_SERVER_URL = 'https://zpasswd-server.favlink.workers.dev';

/**
 * 与同步服务端的 REST 契约（需与 apps/server 对齐）：
 *
 * POST /v1/auth/signup   {email, kdfSalt, authVerifier, wrappedDek:{nonce,ciphertext}} -> 201/200 {}
 * POST /v1/auth/login    {email, authKeyB64} -> 200 {accessJwt, refreshJwt}；401 不区分账号不存在/密码错
 * POST /v1/auth/refresh  {refreshJwt} -> 200 {accessJwt, refreshJwt?}
 * GET  /v1/sync?since=   Authorization: Bearer <accessJwt>（since 为 ISO 字符串）
 *                       -> 200 {items: ServerItem[], serverTime: ISO string}
 * PUT  /v1/items/batch   {items: ServerItem[]} -> 200
 *                       {accepted: string[], rejected: Array<{id: string, item: ServerItem}>}
 *
 * 所有条目在两端都是不透明密文；时间戳统一为 ISO 字符串；version 做乐观并发，
 * 服务端只接受 version 更大的写入。
 */

/** 服务端条目（不含本地 dirty 标记） */
export interface ServerItem {
  id: string;
  nonce: string;
  ciphertext: string;
  version: number;
  folderId: string | null;
  favorite: boolean;
  updatedAt: string;
  deletedAt: string | null;
}

export interface SyncResult {
  skipped?: boolean;
  pushed: number;
  pulled: number;
  conflicts: number;
}

function toStored(s: ServerItem): StoredItem {
  return { ...s, dirty: false };
}

function stripLocal(i: StoredItem): ServerItem {
  const { dirty: _dirty, ...rest } = i;
  return rest;
}

async function authed(state: SyncState, path: string, init: RequestInit): Promise<Response> {
  const base = state.serverUrl.replace(/\/$/, '');
  const doFetch = (token: string) =>
    fetch(base + path, {
      ...init,
      headers: { ...(init.headers ?? {}), Authorization: `Bearer ${token}` },
    });
  let res = await doFetch(state.accessJwt);
  if (res.status === 401 && state.refreshJwt) {
    const r = await fetch(base + '/v1/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshJwt: state.refreshJwt }),
    });
    if (!r.ok) throw new Error('同步登录已过期，请在设置页重新连接同步服务');
    const t = (await r.json()) as { accessJwt: string; refreshJwt?: string };
    state.accessJwt = t.accessJwt;
    if (t.refreshJwt) state.refreshJwt = t.refreshJwt;
    await saveSyncState(state);
    res = await doFetch(state.accessJwt);
  }
  return res;
}

/** 把本地冲突版本存一份副本到"同步冲突"文件夹（改名后重新加密） */
async function stashConflict(
  db: Awaited<ReturnType<typeof getDb>>,
  dek: Uint8Array,
  local: StoredItem,
): Promise<void> {
  await db.put('folders', { id: CONFLICT_FOLDER_ID, name: CONFLICT_FOLDER_NAME });
  const plain = JSON.parse(
    await decryptItem(dek, { nonce: local.nonce, ciphertext: local.ciphertext }),
  ) as VaultItemPlain;
  plain.name = `${plain.name}（冲突副本）`;
  const box = await encryptItem(dek, JSON.stringify(plain));
  await db.put('items', {
    id: crypto.randomUUID(),
    ...box,
    version: 1,
    folderId: CONFLICT_FOLDER_ID,
    favorite: false,
    updatedAt: new Date().toISOString(),
    deletedAt: null,
    dirty: true,
  });
}

export async function runSync(getDek: () => Promise<Uint8Array>): Promise<SyncResult> {
  const state = await getSyncState();
  if (!state?.serverUrl) return { skipped: true, pushed: 0, pulled: 0, conflicts: 0 };
  const dek = await getDek();
  const db = await getDb();
  const since = state.lastSyncAt || '1970-01-01T00:00:00.000Z';

  // 1) 拉取增量
  const pullRes = await authed(state, `/v1/sync?since=${encodeURIComponent(since)}`, {});
  if (!pullRes.ok) throw new Error(`同步拉取失败：HTTP ${pullRes.status}`);
  const pull = (await pullRes.json()) as { items: ServerItem[]; serverTime: string };
  let pulled = 0;
  let conflicts = 0;

  for (const s of pull.items) {
    const local = await db.get('items', s.id);
    if (!local) {
      await db.put('items', toStored(s));
      pulled++;
    } else if (s.version > local.version) {
      if (local.dirty) {
        await stashConflict(db, dek, local);
        conflicts++;
      }
      await db.put('items', toStored(s));
      pulled++;
    }
    // 本地 version >= 服务端且 dirty → 留到推送阶段
  }

  // 2) 推送本地变更（含删除 tombstone）
  const all = await db.getAll('items');
  const dirty = all.filter((i) => i.dirty);
  let pushed = 0;
  if (dirty.length > 0) {
    const pushRes = await authed(state, '/v1/items/batch', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: dirty.map(stripLocal) }),
    });
    if (!pushRes.ok) throw new Error(`同步推送失败：HTTP ${pushRes.status}`);
    const push = (await pushRes.json()) as {
      accepted: string[];
      rejected: Array<{ id: string; item: ServerItem }>;
    };
    const accepted = new Set(push.accepted);
    for (const item of dirty) {
      if (accepted.has(item.id)) {
        const cur = await db.get('items', item.id);
        if (cur) {
          delete cur.dirty;
          await db.put('items', cur);
        }
        pushed++;
      }
    }
    for (const r of push.rejected) {
      const local = await db.get('items', r.id);
      if (local?.dirty) {
        await stashConflict(db, dek, local);
        conflicts++;
      }
      await db.put('items', toStored(r.item));
    }
  }

  state.lastSyncAt = pull.serverTime;
  await saveSyncState(state);
  return { pushed, pulled, conflicts };
}

/** 连接同步服务：尝试登录，账号不存在则自动注册再登录 */
export async function connectSync(args: {
  serverUrl: string;
  email: string;
  deviceName: string;
  getMasterKey: () => Promise<Uint8Array>;
  getVaultIdentity: () => Promise<{ saltB64: string; wrappedDek: { nonce: string; ciphertext: string } }>;
}): Promise<void> {
  const base = args.serverUrl.replace(/\/$/, '');
  if (!/^https?:\/\//.test(base)) throw new Error('服务器地址须以 http(s):// 开头');
  const mk = await args.getMasterKey();
  const authKey = await deriveSubkey(mk, 'auth');
  const authB64 = b64encode(authKey);

  const doLogin = () =>
    fetch(base + '/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: args.email, authKeyB64: authB64 }),
    });

  // 服务端为防账号枚举，登录失败统一返回 401（不区分账号不存在/密码错），
  // 因此连接流程为：登录 → 401 则尝试注册 → 再登录 → 仍 401 则报错。
  let login = await doLogin();
  if (login.status === 401) {
    const { saltB64, wrappedDek } = await args.getVaultIdentity();
    const reg = await fetch(base + '/v1/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: args.email,
        kdfSalt: saltB64,
        authVerifier: await makeAuthVerifier(authKey),
        wrappedDek,
      }),
    });
    if (!reg.ok) throw new Error(`注册失败：HTTP ${reg.status}`);
    login = await doLogin();
  }
  if (!login.ok) throw new Error('登录失败：该邮箱已注册但主密码不正确，或服务器地址有误');
  const t = (await login.json()) as { accessJwt: string; refreshJwt: string };

  const prev = await getSyncState();
  await saveSyncState({
    serverUrl: base,
    email: args.email,
    deviceId: prev?.deviceId || crypto.randomUUID(),
    deviceName: args.deviceName,
    accessJwt: t.accessJwt,
    refreshJwt: t.refreshJwt,
    lastSyncAt: prev?.lastSyncAt ?? '',
  });
}
