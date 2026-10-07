import type { GenerateOptions } from '@pm/crypto';
import type { Credential, ItemMeta, PendingSave, Settings, VaultItemPlain } from './types';

/** background service worker 的消息协议 */
export type BgRequest =
  | { type: 'CREATE_VAULT'; password: string }
  | { type: 'UNLOCK'; password: string }
  | { type: 'VERIFY_PASSWORD'; password: string }
  | { type: 'LOCK' }
  | { type: 'GET_STATUS' }
  | { type: 'LIST_ITEMS'; query?: string }
  | { type: 'GET_ITEM'; id: string }
  | { type: 'GET_CREDENTIALS'; url: string }
  | { type: 'ADD_ITEM'; item: VaultItemPlain; folderId?: string | null }
  | { type: 'UPDATE_ITEM'; id: string; item: VaultItemPlain; folderId?: string | null; favorite?: boolean }
  | { type: 'DELETE_ITEM'; id: string }
  | { type: 'TOGGLE_FAVORITE'; id: string }
  | { type: 'GENERATE'; opts?: GenerateOptions }
  | { type: 'EXPORT' }
  | { type: 'SYNC_NOW' }
  | { type: 'CONNECT_SYNC'; serverUrl: string; email: string }
  | { type: 'DISCONNECT_SYNC' }
  | { type: 'GET_SETTINGS' }
  | { type: 'SAVE_SETTINGS'; settings: Partial<Settings> }
  | { type: 'GET_RECOVERY_MNEMONIC' }
  | { type: 'RECORD_PENDING_SAVE'; entry: Omit<PendingSave, 'createdAt'>; quiet?: boolean }
  | { type: 'CONSUME_PENDING_SAVE' }
  | { type: 'CONFIRM_PENDING_SAVE' }
  | { type: 'DISMISS_PENDING_SAVE' }
  | { type: 'RESET_VAULT' };

export interface BgResponse {
  ok: boolean;
  data?: unknown;
  error?: string;
}

export interface Status {
  hasVault: boolean;
  unlocked: boolean;
  pendingSave: { url: string; username: string } | null;
  syncConfigured: boolean;
  syncEmail?: string;
}

/** 类型安全的 background 调用：失败时抛 Error */
export function bg<T>(req: BgRequest): Promise<T> {
  return chrome.runtime.sendMessage(req).then((res: BgResponse) => {
    if (!res || !res.ok) throw new Error(res?.error || 'background 调用失败');
    return res.data as T;
  });
}

export type { Credential, ItemMeta, Settings, VaultItemPlain };
