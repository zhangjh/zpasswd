import {
  KDF_MEMLIMIT,
  KDF_OPSLIMIT,
  decryptItem,
  deriveMasterKey,
  deriveSubkey,
  encryptItem,
  generatePassword,
  randomKey,
  randomSalt,
  recoveryMnemonicFromMasterKey,
  unwrapDek,
  wipe,
  wrapDek,
} from '@pm/crypto';
import { clearAllData, clearSyncState, getDb, getSyncState, saveSyncState } from './lib/db';
import { connectSync, DEFAULT_SERVER_URL, runSync, type SyncResult } from './lib/sync';
import { b64decode, b64encode, etldPlusOneOfUrl } from './lib/util';
import type { BgRequest, BgResponse, Status } from './lib/messages';
import {
  DEFAULT_SETTINGS,
  type Credential,
  type ItemMeta,
  type PendingSave,
  type Settings,
  type StoredItem,
  type VaultItemPlain,
} from './lib/types';

/**
 * 铁律：MK / DEK / 明文密码只存在于本模块的内存变量与 chrome.storage.session（内存级）；
 * chrome.storage.local 与 IndexedDB 里只有密文、salt、wrappedDek、验证子。
 */

const VAULT_CHECK = 'zpasswd-vault-check-v1';

const LS_KEY = {
  SALT: 'saltB64',
  WRAPPED_DEK: 'wrappedDek',
  VAULT_CHECK: 'vaultCheck',
  SETTINGS: 'settings',
} as const;

let mk: Uint8Array | null = null;
let dek: Uint8Array | null = null;
let lastActiveAt = 0;

const isUnlocked = () => mk !== null && dek !== null;

function fail(message: string): Error {
  return new Error(message);
}

// ---------- 会话（内存级，SW 重启可恢复，浏览器关闭清空） ----------

async function persistSession(): Promise<void> {
  if (mk && dek) {
    await chrome.storage.session.set({ mkB64: b64encode(mk), dekB64: b64encode(dek) });
  } else {
    await chrome.storage.session.remove(['mkB64', 'dekB64']);
  }
}

async function restoreSession(): Promise<void> {
  try {
    const s = await chrome.storage.session.get(['mkB64', 'dekB64', 'pendingSave']);
    if (typeof s.mkB64 === 'string' && typeof s.dekB64 === 'string') {
      mk = b64decode(s.mkB64);
      dek = b64decode(s.dekB64);
      lastActiveAt = Date.now();
    }
  } catch {
    // session storage 不可用时就当未解锁
  }
}

function doLock(): void {
  if (mk) wipe(mk);
  if (dek) wipe(dek);
  mk = null;
  dek = null;
  void persistSession();
}

// ---------- 设置 ----------

async function getSettings(): Promise<Settings> {
  const s = await chrome.storage.local.get(LS_KEY.SETTINGS);
  const saved = (s[LS_KEY.SETTINGS] as Partial<Settings> | undefined) ?? {};
  return { ...DEFAULT_SETTINGS, ...saved };
}

// ---------- 内部工具 ----------

function requireDek(): Uint8Array {
  if (!dek) throw fail('vault 已锁定，请先解锁');
  return dek;
}

async function decryptPlain(box: Pick<StoredItem, 'nonce' | 'ciphertext'>): Promise<VaultItemPlain> {
  return JSON.parse(await decryptItem(requireDek(), box)) as VaultItemPlain;
}

/** 内部：按 eTLD+1 取某 URL 的已存凭证（不检查锁定，调用方负责） */
async function credentialsForUrl(url: string): Promise<Credential[]> {
  const target = etldPlusOneOfUrl(url);
  const creds: Credential[] = [];
  if (!target) return creds;
  const db = await getDb();
  const all = await db.getAll('items');
  for (const it of all) {
    if (it.deletedAt) continue;
    const plain = await decryptPlain(it);
    if (!plain.url) continue;
    if (etldPlusOneOfUrl(plain.url) === target && plain.password) {
      creds.push({ id: it.id, username: plain.username, password: plain.password });
    }
  }
  return creds;
}

/** 待保存提示的小红点：有未处理的保存提示时显示 */
async function setSaveBadge(on: boolean): Promise<void> {
  try {
    await chrome.action.setBadgeText({ text: on ? '1' : '' });
    if (on) await chrome.action.setBadgeBackgroundColor({ color: '#1B2A4A' });
  } catch {
    // 忽略（如 action 不可用）
  }
}

/** 内部：创建一条 vault 条目，返回 id（ADD_ITEM 与 CONFIRM_PENDING_SAVE 共用） */
async function createItem(item: VaultItemPlain, folderId: string | null): Promise<string> {
  const d = requireDek();
  const db = await getDb();
  const box = await encryptItem(d, JSON.stringify(item));
  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  await db.put('items', {
    id,
    ...box,
    version: 1,
    folderId: folderId ?? null,
    favorite: false,
    updatedAt: now,
    deletedAt: null,
    dirty: true,
  });
  return id;
}

/** 有新登录待保存时发系统通知（点击打开 popup 确认）；quiet 时跳过（如页内已弹确认框） */
async function notifySavePrompt(url: string, username: string): Promise<void> {
  try {
    let host = url;
    try {
      host = new URL(url).hostname;
    } catch {
      // keep raw
    }
    await chrome.notifications.create('zpasswd-save-prompt', {
      type: 'basic',
      iconUrl: 'icons/icon-48.png',
      title: 'zpasswd：保存新登录信息？',
      message: `检测到 ${host}${username ? `（${username}）` : ''} 的新登录，点击保存到保险库`,
    });
  } catch {
    // 忽略（如通知被禁用）
  }
}

/** 锁定中收到保存请求：不静默丢弃，发通知告诉用户解锁后可保存（点击打开 popup） */
async function notifyLockedSave(url: string): Promise<void> {
  try {
    let host = url;
    try {
      host = new URL(url).hostname;
    } catch {
      // keep raw
    }
    await chrome.notifications.create('zpasswd-locked-save', {
      type: 'basic',
      iconUrl: 'icons/icon-48.png',
      title: 'zpasswd：检测到新登录',
      message: `保险库已锁定，解锁后可保存 ${host} 的登录信息`,
    });
  } catch {
    // 忽略（如通知被禁用）
  }
}

async function hasVault(): Promise<boolean> {
  const s = await chrome.storage.local.get(LS_KEY.SALT);
  return typeof s[LS_KEY.SALT] === 'string';
}

async function touch(): Promise<void> {
  lastActiveAt = Date.now();
}

// ---------- 自动同步 ----------
//
// 背景：同步此前只由 popup 的「同步」按钮（SYNC_NOW）与「连接同步」（CONNECT_SYNC）
// 触发。新增/修改/删除条目只写本地并打上 dirty 标记，没有任何一处上传，
// 于是服务端永远见不到这些条目 —— 换设备自然拉不到。
// 现在把同步挂到四个时机：解锁后、每次本地写入后、定时兜底、从服务器恢复后。
//
// 串行化：runSync 是「先拉后推 + version 乐观锁」。同一时刻跑两轮时，
// 后一轮推送的 version 会被服务端判定为不更新而拒绝，客户端再把拒绝当冲突处理，
// 于是凭空多出「冲突副本」。所以所有同步请求都排在同一条链上串行执行。

const SYNC_ALARM = 'zpasswd-sync';
const SYNC_INTERVAL_MINUTES = 15;
/** 写入后 / 解锁后最多等这么久；超时就让同步继续在后台跑，不阻塞 UI */
const SYNC_WAIT_MS = 3000;

let syncChain: Promise<unknown> = Promise.resolve();
let autoSyncPending = false;
let autoSyncAgain = false;

const EMPTY_SYNC_RESULT: SyncResult = { skipped: true, pushed: 0, pulled: 0, conflicts: 0 };

async function setSyncError(message: string): Promise<void> {
  const s = await getSyncState();
  if (!s || (s.lastError ?? '') === message) return;
  await saveSyncState({ ...s, lastError: message, lastSyncAttemptAt: new Date().toISOString() });
}

async function clearSyncError(): Promise<void> {
  const s = await getSyncState();
  if (!s || !s.lastError) return;
  await saveSyncState({ ...s, lastError: '', lastSyncAttemptAt: new Date().toISOString() });
}

/** 把一轮同步追加到串行链尾。错误照常抛出，由调用方决定是否吞掉。 */
function enqueueSync(): Promise<SyncResult> {
  const run = async (): Promise<SyncResult> => {
    if (!isUnlocked()) return EMPTY_SYNC_RESULT;
    const state = await getSyncState();
    if (!state?.serverUrl) return EMPTY_SYNC_RESULT;
    try {
      const r = await runSync(async () => requireDek());
      await clearSyncError();
      return r;
    } catch (e) {
      await setSyncError(e instanceof Error ? e.message : String(e));
      throw e;
    }
  };
  const p = syncChain.then(run, run);
  // 链本身不能因某轮失败而断掉，否则后续所有同步都会被静默跳过
  syncChain = p.then(
    () => undefined,
    () => undefined,
  );
  return p;
}

/** 手动 / 连接后 / 恢复后的同步：必须跑一轮，错误抛给调用方展示。 */
function syncNow(): Promise<SyncResult> {
  return enqueueSync();
}

/**
 * 自动同步（写入后 / 解锁后 / 定时兜底）：错误只记进 sync state，不抛出。
 *
 * 合并请求：已有自动同步在跑时只标记「再补一轮」，避免慢网下请求无限堆积；
 * 同时保证在同步过程中新产生的写入一定会被下一轮带上（不丢更新）。
 */
async function autoSync(): Promise<void> {
  if (autoSyncPending) {
    autoSyncAgain = true;
    return;
  }
  autoSyncPending = true;
  try {
    do {
      autoSyncAgain = false;
      await enqueueSync().catch(() => undefined);
    } while (autoSyncAgain);
  } finally {
    autoSyncPending = false;
  }
}

/** 写入后 / 解锁后触发：最多等 SYNC_WAIT_MS，超时后同步继续在后台跑，不阻塞 UI。 */
async function autoSyncWithinBudget(): Promise<void> {
  await Promise.race([
    autoSync(),
    new Promise<void>((resolve) => setTimeout(resolve, SYNC_WAIT_MS)),
  ]);
}

/** 定时兜底同步。MV3 的 SW 会频繁重启，无条件 create 会把周期闹钟一直重置导致永不触发，
 *  所以只在闹钟不存在时创建。 */
void chrome.alarms.get(SYNC_ALARM).then((existing) => {
  if (!existing) void chrome.alarms.create(SYNC_ALARM, { periodInMinutes: SYNC_INTERVAL_MINUTES });
});

// ---------- 消息处理 ----------

async function handle(req: BgRequest): Promise<unknown> {
  await touch();
  switch (req.type) {
    case 'CREATE_VAULT': {
      if (await hasVault()) throw fail('vault 已存在');
      const salt = await randomSalt();
      const nmk = await deriveMasterKey(req.password, salt);
      const kek = await deriveSubkey(nmk, 'enc');
      const ndek = await randomKey();
      const wrapped = await wrapDek(kek, ndek);
      const check = await encryptItem(ndek, VAULT_CHECK);
      wipe(kek);
      await chrome.storage.local.set({
        [LS_KEY.SALT]: b64encode(salt),
        [LS_KEY.WRAPPED_DEK]: wrapped,
        [LS_KEY.VAULT_CHECK]: check,
      });
      mk = nmk;
      dek = ndek;
      await persistSession();
      return { ok: true };
    }

    case 'RESTORE_FROM_SYNC': {
      // 从同步服务器恢复 vault（新设备 / 重装后）。
      // 注意：本地已有 vault 会被覆盖（先清空），因为不同 salt 派生的密钥互不兼容。
      const email = req.email.trim().toLowerCase();
      if (!email) throw fail('请填写邮箱');
      const settings = await getSettings();
      const base = (settings.serverUrl || DEFAULT_SERVER_URL).replace(/\/$/, '');

      // 1. 取服务器上的 salt 与 wrappedDek
      let saltRes: Response;
      try {
        saltRes = await fetch(`${base}/v1/auth/salt?email=${encodeURIComponent(email)}`);
      } catch {
        throw fail('无法连接同步服务器，请检查网络与服务器地址');
      }
      if (saltRes.status === 404) throw fail('该邮箱没有同步账号，请检查邮箱，或先在原设备上连接同步');
      if (!saltRes.ok) throw fail(`获取账号信息失败：HTTP ${saltRes.status}`);
      const { kdfSalt, wrappedDek } = (await saltRes.json()) as {
        kdfSalt: string;
        wrappedDek: { nonce: string; ciphertext: string };
      };

      // 2. 用服务器的 salt 派生 MK（与原设备一致）
      const salt = b64decode(kdfSalt);
      const nmk = await deriveMasterKey(req.password, salt);
      const authKey = await deriveSubkey(nmk, 'auth');

      // 3. 登录验证主密码
      let loginRes: Response;
      try {
        loginRes = await fetch(`${base}/v1/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, authKeyB64: b64encode(authKey) }),
        });
      } catch {
        wipe(nmk);
        wipe(authKey);
        throw fail('无法连接同步服务器');
      }
      if (!loginRes.ok) {
        wipe(nmk);
        wipe(authKey);
        throw fail('主密码不正确');
      }
      const { accessJwt, refreshJwt } = (await loginRes.json()) as {
        accessJwt: string;
        refreshJwt: string;
      };

      // 4. 解出 DEK
      const kek = await deriveSubkey(nmk, 'enc');
      let ndek: Uint8Array;
      try {
        ndek = await unwrapDek(kek, wrappedDek);
      } catch {
        wipe(nmk);
        wipe(kek);
        wipe(authKey);
        throw fail('恢复失败：无法解开数据密钥');
      }
      wipe(kek);
      wipe(authKey);

      // 5. 覆盖本地（清空旧 vault 数据与同步状态）
      await clearAllData();
      await clearSyncState();
      const check = await encryptItem(ndek, VAULT_CHECK);
      await chrome.storage.local.set({
        [LS_KEY.SALT]: kdfSalt,
        [LS_KEY.WRAPPED_DEK]: wrappedDek,
        [LS_KEY.VAULT_CHECK]: check,
      });
      mk = nmk;
      dek = ndek;
      await persistSession();

      // 6. 保存同步状态并拉取。此前这里只写状态没真拉，导致新设备"恢复成功"后保险库是空的，
      //    必须再手动点一次同步才看得到数据。现在恢复完立即拉取。
      const deviceName = settings.deviceName;
      await saveSyncState({
        serverUrl: base,
        email,
        deviceId: crypto.randomUUID(),
        deviceName,
        accessJwt,
        refreshJwt,
        lastSyncAt: '',
      });
      // 拉取失败不回滚本地恢复结果；错误已记入 sync state，popup 会提示
      await autoSync();
      return { ok: true };
    }

    case 'UNLOCK': {
      const s = await chrome.storage.local.get([LS_KEY.SALT, LS_KEY.WRAPPED_DEK, LS_KEY.VAULT_CHECK]);
      if (typeof s[LS_KEY.SALT] !== 'string') throw fail('vault 不存在，请先创建');
      const salt = b64decode(s[LS_KEY.SALT] as string);
      const nmk = await deriveMasterKey(req.password, salt);
      const kek = await deriveSubkey(nmk, 'enc');
      let ndek: Uint8Array;
      try {
        ndek = await unwrapDek(kek, s[LS_KEY.WRAPPED_DEK] as { nonce: string; ciphertext: string });
        const probe = await decryptItem(ndek, s[LS_KEY.VAULT_CHECK] as { nonce: string; ciphertext: string });
        if (probe !== VAULT_CHECK) throw new Error('check mismatch');
      } catch {
        wipe(nmk);
        wipe(kek);
        throw fail('主密码错误');
      }
      wipe(kek);
      mk = nmk;
      dek = ndek;
      await persistSession();
      // 解锁后立刻拉一次远端增量：换设备 / 别的设备刚改过时，打开就是最新的。
      // 未连接同步时直接返回，不产生任何网络请求。
      await autoSyncWithinBudget();
      return { ok: true };
    }

    case 'VERIFY_PASSWORD': {
      // 只验证不改变解锁状态（恢复码展示前的二次确认用）
      const s = await chrome.storage.local.get([LS_KEY.SALT, LS_KEY.WRAPPED_DEK, LS_KEY.VAULT_CHECK]);
      if (typeof s[LS_KEY.SALT] !== 'string') throw fail('vault 不存在');
      const nmk = await deriveMasterKey(req.password, b64decode(s[LS_KEY.SALT] as string));
      const kek = await deriveSubkey(nmk, 'enc');
      try {
        const ndek = await unwrapDek(kek, s[LS_KEY.WRAPPED_DEK] as { nonce: string; ciphertext: string });
        const probe = await decryptItem(ndek, s[LS_KEY.VAULT_CHECK] as { nonce: string; ciphertext: string });
        if (probe !== VAULT_CHECK) throw new Error('check mismatch');
        wipe(ndek);
      } catch {
        throw fail('主密码错误');
      } finally {
        wipe(nmk);
        wipe(kek);
      }
      return { ok: true };
    }

    case 'LOCK': {
      doLock();
      return { ok: true };
    }

    case 'GET_STATUS': {
      const hv = await hasVault();
      const sess = await chrome.storage.session.get('pendingSave');
      const pending = (sess.pendingSave as PendingSave | undefined) ?? null;
      const sync = await getSyncState();
      const settings = await getSettings();
      const status: Status = {
        hasVault: hv,
        unlocked: isUnlocked(),
        pendingSave: pending ? { url: pending.url, username: pending.username } : null,
        syncConfigured: !!sync?.serverUrl,
        syncEmail: sync?.email || settings.email || undefined,
        lastSyncAt: sync?.lastSyncAt || undefined,
        syncError: sync?.lastError || undefined,
      };
      return status;
    }

    case 'LIST_ITEMS': {
      requireDek();
      const db = await getDb();
      const all = await db.getAll('items');
      const q = (req.query ?? '').trim().toLowerCase();
      const metas: ItemMeta[] = [];
      for (const it of all) {
        if (it.deletedAt) continue;
        const plain = await decryptPlain(it);
        if (
          q &&
          !`${plain.name} ${plain.username} ${plain.url}`.toLowerCase().includes(q)
        ) {
          continue;
        }
        metas.push({
          id: it.id,
          name: plain.name,
          username: plain.username,
          url: plain.url,
          folderId: it.folderId,
          favorite: it.favorite,
          updatedAt: it.updatedAt,
        });
      }
      metas.sort((a, b) => Number(b.favorite) - Number(a.favorite) || b.updatedAt.localeCompare(a.updatedAt));
      return metas;
    }

    case 'GET_ITEM': {
      requireDek();
      const db = await getDb();
      const it = await db.get('items', req.id);
      if (!it || it.deletedAt) throw fail('条目不存在');
      const plain = await decryptPlain(it);
      return { meta: { id: it.id, folderId: it.folderId, favorite: it.favorite }, plain };
    }

    case 'GET_CREDENTIALS': {
      // 锁定状态下直接返回空，不泄露任何信息
      if (!isUnlocked()) return { locked: true, credentials: [] as Credential[] };
      return { locked: false, credentials: await credentialsForUrl(req.url) };
    }

    case 'ADD_ITEM': {
      const id = await createItem(req.item, req.folderId ?? null);
      await autoSyncWithinBudget();
      return { id };
    }

    case 'UPDATE_ITEM': {
      const d = requireDek();
      const db = await getDb();
      const it = await db.get('items', req.id);
      if (!it || it.deletedAt) throw fail('条目不存在');
      const box = await encryptItem(d, JSON.stringify(req.item));
      await db.put('items', {
        ...it,
        ...box,
        version: it.version + 1,
        folderId: req.folderId ?? it.folderId,
        favorite: req.favorite ?? it.favorite,
        updatedAt: new Date().toISOString(),
        dirty: true,
      });
      await autoSyncWithinBudget();
      return { ok: true };
    }

    case 'DELETE_ITEM': {
      requireDek();
      const db = await getDb();
      const it = await db.get('items', req.id);
      if (!it || it.deletedAt) throw fail('条目不存在');
      await db.put('items', {
        ...it,
        version: it.version + 1,
        updatedAt: new Date().toISOString(),
        deletedAt: new Date().toISOString(),
        dirty: true,
      });
      await autoSyncWithinBudget();
      return { ok: true };
    }

    case 'TOGGLE_FAVORITE': {
      requireDek();
      const db = await getDb();
      const it = await db.get('items', req.id);
      if (!it || it.deletedAt) throw fail('条目不存在');
      await db.put('items', {
        ...it,
        favorite: !it.favorite,
        version: it.version + 1,
        updatedAt: new Date().toISOString(),
        dirty: true,
      });
      await autoSyncWithinBudget();
      return { favorite: !it.favorite };
    }

    case 'GENERATE': {
      return generatePassword(req.opts ?? {});
    }

    case 'EXPORT': {
      requireDek();
      const s = await chrome.storage.local.get([LS_KEY.SALT, LS_KEY.WRAPPED_DEK]);
      const db = await getDb();
      const all = await db.getAll('items');
      return {
        format: 'zpasswd-export-v1',
        exportedAt: new Date().toISOString(),
        saltB64: s[LS_KEY.SALT],
        wrappedDek: s[LS_KEY.WRAPPED_DEK],
        kdfParams: { opslimit: KDF_OPSLIMIT, memlimit: KDF_MEMLIMIT },
        items: all.map(({ dirty: _d, ...rest }) => rest),
      };
    }

    case 'SYNC_NOW': {
      // 手动同步：与自动同步共用同一条串行链，错误抛给调用方展示
      return syncNow();
    }

    case 'CONNECT_SYNC': {
      if (!mk) throw fail('请先解锁 vault');
      const settings = await getSettings();
      await connectSync({
        serverUrl: req.serverUrl,
        email: req.email,
        deviceName: settings.deviceName,
        getMasterKey: async () => {
          if (!mk) throw fail('vault 已锁定');
          return mk;
        },
        getVaultIdentity: async () => {
          const s = await chrome.storage.local.get([LS_KEY.SALT, LS_KEY.WRAPPED_DEK]);
          return {
            saltB64: s[LS_KEY.SALT] as string,
            wrappedDek: s[LS_KEY.WRAPPED_DEK] as { nonce: string; ciphertext: string },
          };
        },
      });
      await chrome.storage.local.set({
        [LS_KEY.SETTINGS]: { ...settings, serverUrl: req.serverUrl, email: req.email },
      });
      // 连接成功后立即同步一次
      return syncNow();
    }

    case 'DISCONNECT_SYNC': {
      await clearSyncState();
      return { ok: true };
    }

    case 'GET_SETTINGS': {
      return getSettings();
    }

    case 'SAVE_SETTINGS': {
      const cur = await getSettings();
      const next = { ...cur, ...req.settings };
      await chrome.storage.local.set({ [LS_KEY.SETTINGS]: next });
      return next;
    }

    case 'GET_RECOVERY_MNEMONIC': {
      if (!mk) throw fail('请先解锁 vault');
      return { mnemonic: await recoveryMnemonicFromMasterKey(mk) };
    }

    case 'RECORD_PENDING_SAVE': {
      // 未解锁时不静默丢弃：发通知引导用户解锁（解锁后重新登录一次即可保存）。
      // 解锁检查与去重都在这里做，content 端只做同步抓值 + 单条消息。
      if (!isUnlocked()) {
        await notifyLockedSave(req.entry.url);
        return { ok: true };
      }
      const username = req.entry.username ?? '';
      const creds = await credentialsForUrl(req.entry.url);
      if (creds.some((c) => c.username === username)) return { ok: true };
      const entry: PendingSave = {
        url: req.entry.url,
        username,
        password: req.entry.password,
        createdAt: Date.now(),
      };
      await chrome.storage.session.set({ pendingSave: entry });
      await setSaveBadge(true);
      // 主动触达：非 quiet 时再发一条系统通知（quiet 表示调用方页内已弹确认框）
      if (!req.quiet) await notifySavePrompt(entry.url, entry.username);
      return { ok: true };
    }

    case 'CONFIRM_PENDING_SAVE': {
      // 页内确认框点了"保存"：直接消费并入库（与 popup 的保存按钮等价）
      const sess = await chrome.storage.session.get('pendingSave');
      const p = (sess.pendingSave as PendingSave | undefined) ?? null;
      if (!p) throw fail('没有待保存的登录信息');
      await chrome.storage.session.remove('pendingSave');
      await setSaveBadge(false);
      try {
        void chrome.notifications.clear('zpasswd-save-prompt');
      } catch {
        // ignore
      }
      let site = p.url;
      try {
        site = new URL(p.url).hostname;
      } catch {
        // keep raw
      }
      const id = await createItem(
        { name: site, username: p.username, password: p.password, url: p.url, notes: '', totpSeed: '' },
        null,
      );
      await autoSyncWithinBudget();
      return { id };
    }

    case 'CONSUME_PENDING_SAVE': {
      const sess = await chrome.storage.session.get('pendingSave');
      const p = (sess.pendingSave as PendingSave | undefined) ?? null;
      await chrome.storage.session.remove('pendingSave');
      await setSaveBadge(false);
      return p;
    }

    case 'DISMISS_PENDING_SAVE': {
      await chrome.storage.session.remove('pendingSave');
      await setSaveBadge(false);
      return { ok: true };
    }

    case 'RESET_VAULT': {
      doLock();
      await chrome.storage.local.clear();
      await chrome.storage.session.clear();
      await clearAllData();
      return { ok: true };
    }

    case 'SHOW_SAVE_PROMPT': {
      // 实际在 onMessage listener 里直接处理（需要 sender.tab），到这里说明逻辑有误
      throw fail('SHOW_SAVE_PROMPT 不应走 handle()');
    }

    default: {
      const _exhaustive: never = req;
      throw fail(`未知消息：${JSON.stringify(_exhaustive)}`);
    }
  }
}

// ---------- 启动 ----------

// SW 启动时恢复会话；消息处理等待恢复完成，避免竞态导致误判未解锁
const sessionReady = restoreSession();

chrome.runtime.onMessage.addListener(
  (req: BgRequest, sender, sendResponse: (r: BgResponse) => void) => {
    // SHOW_SAVE_PROMPT 需要 sender 的 tab 信息，直接在此处理（转发到该 tab 的顶层 frame）
    if ((req as { type?: string }).type === 'SHOW_SAVE_PROMPT') {
      const tabId = sender.tab?.id;
      const username = (req as { username?: string }).username ?? '';
      if (tabId === undefined) {
        sendResponse({ ok: false, error: '无 tab 信息' });
      } else {
        const msg = { type: 'SHOW_SAVE_PROMPT', username } as unknown as never;
        chrome.tabs
          .sendMessage(tabId, msg, { frameId: 0 })
          .then(() => sendResponse({ ok: true, data: null }))
          .catch(async (e: unknown) => {
            // 顶层 frame 转发失败（如无 content script）：降级为系统通知，避免只剩角标
            try {
              const s = await chrome.storage.session.get('pendingSave');
              const pending = s.pendingSave as { url?: string; username?: string } | undefined;
              if (pending?.url) {
                await notifySavePrompt(pending.url, pending.username ?? '');
              }
            } catch {
              // 忽略降级失败
            }
            sendResponse({ ok: false, error: String(e) });
          });
      }
      return true;
    }
    sessionReady
      .then(() => handle(req))
      .then((data) => sendResponse({ ok: true, data }))
      .catch((e: unknown) => sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) }));
    return true; // 保持异步响应通道
  },
);

// 保存相关通知：点击打开 popup（用户确认入库）
chrome.notifications.onClicked.addListener((id) => {
  if (id !== 'zpasswd-locked-save' && id !== 'zpasswd-save-prompt') return;
  try {
    // clear 在部分类型定义中返回 void，不链式调用
    void chrome.notifications.clear(id);
  } catch {
    // ignore
  }
  chrome.action.openPopup().catch(() => undefined);
});

// 空闲自动锁定：每分钟检查一次；同步兜底：每 SYNC_INTERVAL_MINUTES 分钟一次
chrome.alarms.create('zpasswd-autolock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SYNC_ALARM) {
    // 定时兜底：万一某次写入后的同步因 SW 被回收等原因没跑完，这里补上。
    // 锁定状态 / 未连接同步时 autoSync 直接返回，不会有网络开销。
    void autoSync();
    return;
  }
  if (alarm.name !== 'zpasswd-autolock') return;
  void (async () => {
    if (!isUnlocked()) return;
    const settings = await getSettings();
    if (Date.now() - lastActiveAt > settings.idleMinutes * 60_000) {
      doLock();
    }
  })();
});

void sessionReady;

// SW 重启后恢复待保存提示的小红点
void chrome.storage.session.get('pendingSave').then((s) => {
  if (s.pendingSave) void setSaveBadge(true);
});
