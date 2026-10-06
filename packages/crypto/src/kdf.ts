import sodium from 'libsodium-wrappers-sumo';

/**
 * KDF 参数 —— 冻结参数，修改需人工 review 并同步扩展/服务端。
 * Argon2id: opslimit=3, memlimit=64MiB。单次派生在桌面端约 0.5~1.5s，
 * 这是刻意为之的成本（防暴力破解），只在解锁/注册/换密码时执行一次。
 */
export const KDF_OPSLIMIT = 3;
export const KDF_MEMLIMIT = 67_108_864; // 64 MiB
export const KDF_SALT_BYTES = 16;
export const KEY_BYTES = 32;

/**
 * crypto_kdf context 必须恰好 8 字节。用不同 context 做用途隔离：
 * 登录凭证（auth）与解密密钥（enc）数学上不可互推 —— 这是零知识的关键。
 */
const SUBKEY_CONTEXTS = {
  enc: 'PMENCv10',
  auth: 'PMAUTHv1',
  rec: 'PMRECv10',
} as const;
export type SubkeyPurpose = keyof typeof SUBKEY_CONTEXTS;

/** 主密码 -> 主密钥 MK（32 字节）。MK 只驻内存，永不落盘。 */
export async function deriveMasterKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  await sodium.ready;
  if (salt.length !== KDF_SALT_BYTES) throw new Error(`salt must be ${KDF_SALT_BYTES} bytes`);
  return sodium.crypto_pwhash(
    KEY_BYTES,
    password,
    salt,
    KDF_OPSLIMIT,
    KDF_MEMLIMIT,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/** MK -> 用途子密钥（enc: 数据密钥封装 / auth: 登录凭证 / rec: 恢复码派生）。 */
export async function deriveSubkey(masterKey: Uint8Array, purpose: SubkeyPurpose): Promise<Uint8Array> {
  await sodium.ready;
  if (masterKey.length !== KEY_BYTES) throw new Error('masterKey must be 32 bytes');
  return sodium.crypto_kdf_derive_from_key(KEY_BYTES, 1, SUBKEY_CONTEXTS[purpose], masterKey);
}

export async function randomSalt(): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(KDF_SALT_BYTES);
}

export async function randomKey(): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(KEY_BYTES);
}

/** 用内存清零覆盖敏感字节。调用后原引用不可再用。 */
export function wipe(buf: Uint8Array): void {
  sodium.memzero(buf);
}

/**
 * 为 AuthKey 生成服务端可存储的验证子（客户端在注册/换密码时计算一次后上传）。
 *
 * 注意：这里用的是 SHA-256 而非 Argon2id —— 这是深思熟虑的取舍：
 * authKey 是 256 位随机密钥（HKDF 派生），不是人类弱密码，SHA-256 的原像抗性
 * 已足够（偷库者逆不出 256 位原像）；而真正的慢哈希保护（Argon2id 64MB）
 * 发生在客户端"主密码 → MK"那一步。同步服务跑在 Cloudflare Workers 上，
 * 单请求 CPU 时间只有 10ms 量级，Argon2id 会被直接掐掉，用 SHA-256 是
 * 在这种约束下的正确选择。服务端只做 SHA-256 比对，永远接触不到主密码/MK。
 */
export async function makeAuthVerifier(authKey: Uint8Array): Promise<string> {
  await sodium.ready;
  if (authKey.length !== KEY_BYTES) throw new Error('authKey must be 32 bytes');
  const digest = sodium.crypto_hash_sha256(authKey);
  return sodium.to_base64(digest, sodium.base64_variants.ORIGINAL);
}

/** 校验登录时提交的 AuthKey：SHA-256 后做恒定时间比较，防时序攻击。 */
export async function verifyAuthKey(authKey: Uint8Array, verifier: string): Promise<boolean> {
  await sodium.ready;
  if (authKey.length !== KEY_BYTES) return false;
  const digest = sodium.crypto_hash_sha256(authKey);
  let expected: Uint8Array;
  try {
    expected = sodium.from_base64(verifier, sodium.base64_variants.ORIGINAL);
  } catch {
    return false;
  }
  if (expected.length !== sodium.crypto_hash_sha256_BYTES) return false;
  return sodium.memcmp(digest, expected);
}
