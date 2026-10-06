/**
 * 认证模块。服务端唯一的密码学操作：authKey 验签（登录）。
 *
 * 设计取舍（与 @pm/crypto/src/kdf.ts 的 makeAuthVerifier 配套）：
 * authKey 是 256 位随机密钥，服务端存 SHA-256(authKey) 做校验即可——
 * 偷库者逆不出 256 位原像，而慢哈希（Argon2id 64MB）在 Workers 的
 * 10ms CPU 限额下会被直接掐掉。真正的慢哈希保护在客户端
 * （主密码 → MK 的 Argon2id），服务端只做快速比对。用 WebCrypto 原生实现，
 * 零依赖、微秒级。
 *
 * 互通约定：客户端用 libsodium crypto_hash_sha256(authKey bytes)，
 * base64(ORIGINAL) 编码后上传为 authVerifier；服务端对提交的 authKeyB64
 * 解码 → SHA-256 → base64 → 恒定时间比较。
 */
import { jwtVerify, SignJWT } from 'jose';
import { Hono } from 'hono';
import type { Context, Next } from 'hono';

export interface Env {
  DB: D1Database;
  JWT_SECRET: string;
}

export type App = Hono<{ Bindings: Env; Variables: { userId: string } }>;

const ACCESS_TTL = '15m';
const REFRESH_TTL = '30d';

function b64ToBytes(s: string): Uint8Array | null {
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function bytesToB64(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}

/** 恒定时间比较（防时序攻击）。 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** 校验登录提交的 authKey。输入畸形时一律返回 false，永不抛异常。 */
export async function verifyAuthKey(authKeyB64: string, verifier: string): Promise<boolean> {
  try {
    const keyBytes = b64ToBytes(authKeyB64);
    const expected = b64ToBytes(verifier);
    if (!keyBytes || keyBytes.length !== 32 || !expected || expected.length !== 32) return false;
    const digest = new Uint8Array(
      // 拷贝一份以拿到 ArrayBuffer-backed 的视图，满足 TS 的 BufferSource 类型
      await crypto.subtle.digest('SHA-256', new Uint8Array(keyBytes)),
    );
    return timingSafeEqual(digest, expected);
  } catch {
    return false;
  }
}

/**
 * 用户不存在时的"假验签"：对固定哑值跑一次同样的 SHA-256 流程，
 * 让"用户不存在"与"密码错误"的耗时不可区分，防时序枚举账号。
 * isolate 内懒计算一次（微秒级，开销可忽略）。
 */
let dummyVerifier: string | null = null;

export async function getDummyVerifier(): Promise<string> {
  if (!dummyVerifier) {
    const digest = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode('zpasswd-dummy-auth-key')),
    );
    dummyVerifier = bytesToB64(digest);
  }
  return dummyVerifier;
}

// ---------------------------------------------------------------- JWT ----

function jwtSecret(env: Env): Uint8Array {
  return new TextEncoder().encode(env.JWT_SECRET);
}

export async function signAccessToken(env: Env, userId: string): Promise<string> {
  return new SignJWT({ typ: 'access' })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(ACCESS_TTL)
    .sign(jwtSecret(env));
}

export async function signRefreshToken(env: Env, userId: string): Promise<{ token: string; jti: string }> {
  const jti = crypto.randomUUID();
  const token = await new SignJWT({ typ: 'refresh', jti })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime(REFRESH_TTL)
    .sign(jwtSecret(env));
  return { token, jti };
}

export interface RefreshPayload {
  sub: string;
  jti: string;
  exp: number;
}

/** 验 refresh token，非法返回 null（不抛异常，调用方统一 401）。 */
export async function verifyRefreshToken(env: Env, token: string): Promise<RefreshPayload | null> {
  try {
    const { payload } = await jwtVerify(token, jwtSecret(env), { algorithms: ['HS256'] });
    if (payload.typ !== 'refresh' || typeof payload.sub !== 'string' || typeof payload.jti !== 'string') {
      return null;
    }
    return { sub: payload.sub, jti: payload.jti, exp: Number(payload.exp ?? 0) };
  } catch {
    return null;
  }
}

/** accessJwt 中间件：通过则 c.set('userId', sub)，否则 401。 */
export async function requireAuth(c: Context<{ Bindings: Env; Variables: { userId: string } }>, next: Next) {
  const m = /^Bearer (.+)$/.exec(c.req.header('Authorization') ?? '');
  if (!m) return c.json({ error: 'unauthorized' }, 401);
  try {
    const { payload } = await jwtVerify(m[1], jwtSecret(c.env), { algorithms: ['HS256'] });
    if (payload.typ !== 'access' || typeof payload.sub !== 'string') throw new Error('bad token');
    c.set('userId', payload.sub);
    await next();
  } catch {
    return c.json({ error: 'unauthorized' }, 401);
  }
}

// ------------------------------------------------------------ 限流 ----

/**
 * 登录限流：(IP + email) 滑动窗口 60 秒 10 次。
 * 注意：内存 Map 是按 isolate 的，Workers 多实例下是近似限流
 * （单个实例打满仍会被限，分布式精确限流需 Durable Object，此处够用）。
 */
const loginAttempts = new Map<string, number[]>();
const WINDOW_MS = 60_000;
const MAX_ATTEMPTS = 10;

export function loginRateLimited(ip: string, email: string): boolean {
  const key = `${ip}:${email.toLowerCase()}`;
  const now = Date.now();
  const recent = (loginAttempts.get(key) ?? []).filter((t) => now - t < WINDOW_MS);
  if (recent.length >= MAX_ATTEMPTS) return true;
  recent.push(now);
  loginAttempts.set(key, recent);
  // 防止 Map 无限增长：偶发清理
  if (loginAttempts.size > 20000) {
    for (const [k, v] of loginAttempts) {
      if (v.length === 0 || now - v[v.length - 1] > WINDOW_MS) loginAttempts.delete(k);
    }
  }
  return false;
}
