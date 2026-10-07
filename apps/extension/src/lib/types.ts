/** 解密后的条目明文结构（只在内存中存在，永不落盘） */
export interface VaultItemPlain {
  name: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpSeed: string;
  customFields?: Array<{ key: string; value: string }>;
}

/** IndexedDB / 服务端存储的密文记录 */
export interface StoredItem {
  id: string;
  nonce: string; // base64
  ciphertext: string; // base64
  version: number;
  folderId: string | null;
  favorite: boolean;
  updatedAt: string; // ISO
  deletedAt: string | null; // ISO，软删
  /** 本地未同步标记，不上传服务端 */
  dirty?: boolean;
}

export interface ItemMeta {
  id: string;
  name: string;
  username: string;
  url: string;
  folderId: string | null;
  favorite: boolean;
  updatedAt: string;
}

export interface Credential {
  id: string;
  username: string;
  password: string;
}

export interface Settings {
  /** 空闲多少分钟后自动锁定 */
  idleMinutes: number;
  /** 同步服务器地址，为空 = 尚未连接同步 */
  serverUrl: string;
  email: string;
  deviceName: string;
}

export const DEFAULT_SETTINGS: Settings = {
  idleMinutes: 5,
  serverUrl: '',
  email: '',
  deviceName: '浏览器',
};

/** 同步冲突副本自动归入的文件夹 */
export const CONFLICT_FOLDER_ID = 'folder-conflict';
export const CONFLICT_FOLDER_NAME = '同步冲突';

export interface PendingSave {
  url: string;
  username: string;
  password: string;
  createdAt: number;
}
