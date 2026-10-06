import { openDB, type DBSchema, type IDBPDatabase } from 'idb';
import type { StoredItem } from './types';

/** 同步连接状态（只存令牌与游标，不存任何密钥/明文） */
export interface SyncState {
  serverUrl: string;
  email: string;
  deviceId: string;
  deviceName: string;
  accessJwt: string;
  refreshJwt: string;
  /** 上次同步成功的服务端时间；'' = 从未同步 */
  lastSyncAt: string;
}

interface PmSchema extends DBSchema {
  items: {
    key: string;
    value: StoredItem;
    indexes: { 'by-updated': string };
  };
  folders: {
    key: string;
    value: { id: string; name: string };
  };
  /** 通用 kv：预留 */
  meta: {
    key: string;
    value: unknown;
  };
  /** 同步状态：固定 key='state' 存一份 SyncState */
  sync: {
    key: string;
    value: SyncState;
  };
}

let dbp: Promise<IDBPDatabase<PmSchema>> | null = null;

/** 注意：IndexedDB 里只存密文。密钥/明文永不入内。 */
export function getDb(): Promise<IDBPDatabase<PmSchema>> {
  if (!dbp) {
    dbp = openDB<PmSchema>('zpasswd', 1, {
      upgrade(db) {
        const items = db.createObjectStore('items', { keyPath: 'id' });
        items.createIndex('by-updated', 'updatedAt');
        db.createObjectStore('folders', { keyPath: 'id' });
        db.createObjectStore('meta');
        db.createObjectStore('sync');
      },
    });
  }
  return dbp;
}

export async function getSyncState(): Promise<SyncState | undefined> {
  return (await getDb()).get('sync', 'state');
}

export async function saveSyncState(s: SyncState): Promise<void> {
  await (await getDb()).put('sync', s, 'state');
}

export async function clearSyncState(): Promise<void> {
  await (await getDb()).delete('sync', 'state');
}

/** 清空全部本地数据（重置 vault 用） */
export async function clearAllData(): Promise<void> {
  const db = await getDb();
  await Promise.all([
    db.clear('items'),
    db.clear('folders'),
    db.clear('meta'),
    db.clear('sync'),
  ]);
}
