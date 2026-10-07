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
import { clearAllData, clearSyncState, getDb, getSyncState } from './lib/db';
import { connectSync, runSync } from './lib/sync';
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

async function hasVault(): Promise<boolean> {
  const s = await chrome.storage.local.get(LS_KEY.SALT);
  return typeof s[LS_KEY.SALT] === 'string';
}

async function touch(): Promise<void> {
  lastActiveAt = Date.now();
}

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
      const d = requireDek();
      const db = await getDb();
      const box = await encryptItem(d, JSON.stringify(req.item));
      const now = new Date().toISOString();
      const id = crypto.randomUUID();
      await db.put('items', {
        id,
        ...box,
        version: 1,
        folderId: req.folderId ?? null,
        favorite: false,
        updatedAt: now,
        deletedAt: null,
        dirty: true,
      });
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
      return runSync(async () => requireDek());
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
      return runSync(async () => requireDek());
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
      // 未解锁时静默忽略；已存在的凭证不重复提示。只放内存级 session storage，不落盘。
      // content 端只做同步抓值 + 单条消息（页面可能正在卸载），解锁检查与去重都在这里做。
      if (!isUnlocked()) return { ok: true };
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
      return { ok: true };
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

    default: {
      const _exhaustive: never = req;
      throw fail(`未知消息：${JSON.stringify(_exhaustive)}`);
    }
  }
}

// ---------- 启动 ----------

chrome.runtime.onMessage.addListener(
  (req: BgRequest, _sender, sendResponse: (r: BgResponse) => void) => {
    handle(req)
      .then((data) => sendResponse({ ok: true, data }))
      .catch((e: unknown) => sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) }));
    return true; // 保持异步响应通道
  },
);

// 空闲自动锁定：每分钟检查一次
chrome.alarms.create('zpasswd-autolock', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'zpasswd-autolock') return;
  if (!isUnlocked()) return;
  const settings = await getSettings();
  if (Date.now() - lastActiveAt > settings.idleMinutes * 60_000) {
    doLock();
  }
});

void restoreSession();

// SW 重启后恢复待保存提示的小红点
void chrome.storage.session.get('pendingSave').then((s) => {
  if (s.pendingSave) void setSaveBadge(true);
});
