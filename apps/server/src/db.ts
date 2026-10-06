/**
 * D1 查询封装。注意：所有读出的 ciphertext/nonce 都是不透明密文，
 * 本文件及整个服务端永远不尝试解密。
 */

export interface UserRow {
  id: string;
  email: string;
  kdf_salt: string;
  auth_verifier: string;
  wrapped_dek_nonce: string;
  wrapped_dek_ct: string;
  recovery_verifier: string;
  created_at: number;
}

export interface VaultItemRow {
  id: string;
  user_id: string;
  nonce: string;
  ciphertext: string;
  version: number;
  folder_id: string | null;
  favorite: number;
  updated_at: number;
  deleted_at: number | null;
}

export interface DeviceRow {
  id: string;
  user_id: string;
  pubkey: string;
  name: string;
  created_at: number;
  revoked_at: number | null;
}

export async function getUserByEmail(db: D1Database, email: string): Promise<UserRow | null> {
  return db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<UserRow>();
}

export async function getUserById(
  db: D1Database,
  userId: string,
): Promise<Pick<UserRow, 'id' | 'kdf_salt' | 'wrapped_dek_nonce' | 'wrapped_dek_ct'> | null> {
  return db
    .prepare('SELECT id, kdf_salt, wrapped_dek_nonce, wrapped_dek_ct FROM users WHERE id = ?')
    .bind(userId)
    .first<Pick<UserRow, 'id' | 'kdf_salt' | 'wrapped_dek_nonce' | 'wrapped_dek_ct'>>();
}

/** 行 -> API 的 camelCase 形状（时间戳转 ISO 字符串，与扩展端一致）。 */
export function toItemJson(r: VaultItemRow) {
  return {
    id: r.id,
    nonce: r.nonce,
    ciphertext: r.ciphertext,
    version: r.version,
    folderId: r.folder_id,
    favorite: r.favorite === 1,
    updatedAt: new Date(r.updated_at).toISOString(),
    deletedAt: r.deleted_at == null ? null : new Date(r.deleted_at).toISOString(),
  };
}
