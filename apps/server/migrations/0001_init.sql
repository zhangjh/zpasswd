-- zpasswd D1 schema
-- 铁律：这里只存密文与验证子。auth_verifier 是 Argon2id(authKey) 的 PHC 字符串，
-- 只能用于登录校验，不能解密任何数据（authKey 与解密密钥在客户端经不同 KDF
-- context 派生，数学上不可互推）。

CREATE TABLE IF NOT EXISTS users (
  id                TEXT PRIMARY KEY,
  email             TEXT UNIQUE NOT NULL,
  kdf_salt          TEXT NOT NULL,  -- base64，客户端派生主密钥用
  auth_verifier     TEXT NOT NULL,  -- $argon2id$v=19$... PHC，仅登录校验
  wrapped_dek_nonce TEXT NOT NULL,  -- base64，KEK 包裹 DEK 的 nonce
  wrapped_dek_ct    TEXT NOT NULL,  -- base64，KEK 包裹 DEK 的密文
  recovery_verifier TEXT,  -- $argon2id$v=19$... PHC，恢复码校验用
  created_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS devices (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id),
  pubkey     TEXT NOT NULL,  -- base64，设备公钥（未来做设备间授权用）
  name       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER          -- 非空 = 已吊销
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

CREATE TABLE IF NOT EXISTS vault_items (
  id         TEXT NOT NULL,   -- 客户端生成的 UUID
  user_id    TEXT NOT NULL REFERENCES users(id),
  nonce      TEXT NOT NULL,   -- base64，XChaCha20-Poly1305 nonce
  ciphertext TEXT NOT NULL,   -- base64，条目明文 JSON 的密文（服务端永不解析）
  version    INTEGER NOT NULL, -- 乐观锁版本号，单调递增
  folder_id  TEXT,
  favorite   INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL, -- 毫秒时间戳，增量同步游标
  deleted_at INTEGER,          -- 非空 = 软删除
  PRIMARY KEY (user_id, id)
);
CREATE INDEX IF NOT EXISTS idx_items_sync ON vault_items(user_id, updated_at);

CREATE TABLE IF NOT EXISTS folders (
  id      TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name    TEXT NOT NULL
);

-- 已吊销的 refresh token jti（rotation 时写入，到期后可清理）
CREATE TABLE IF NOT EXISTS refresh_revoked (
  jti        TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_exp ON refresh_revoked(expires_at);
