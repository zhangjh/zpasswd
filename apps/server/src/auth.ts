/**
 * 认证模块。服务端唯一的密码学操作：argon2id 验签（登录）。
 * 用 hash-wasm（纯 WASM，Workers 原生），不引入 libsodium。
 *
 * 互通约定（已实测）：客户端用 libsodium crypto_pwhash_str 对
 * base64(ORIGINAL) 编码的 32 字节 authKey 生成 $argon2id$v=19$... PHC
 * 字符串上传为 authVerifier；服务端 argon2Verify({ password: authKeyB64,
 * hash: verifier }) 返回 true/false。password 必须是完全相同的字符串。
 */
import { argon2Verify, argon2id } from 'hash-wasm';
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

/** 校验登录提交的 authKey。verifier 畸形时一律返回 false，永不抛异常。 */
export async function verifyAuthKey(authKeyB64: string, verifier: string): Promise<boolean> {
  try {
    return await argon2Verify({ password: authKeyB64, hash: verifier });
  } catch {
    return false;
  }
}

/**
 * 用户不存在时的"假验签"：用同等量级参数跑一次 argon2id，
 * 让"用户不存在"与"密码错误"的耗时不可区分，防时序枚举账号。
 * 按 isolate 懒生成一次。
 */
let dummyHash: string | null = null;
export async function getDummyVerifier(): Promise<string> {
  if (!dummyHash) {
    // 参数与客户端 crypto_pwhash_str(OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE)
    // 同量级（t=2, m=64MB；memorySize 单位为 KiB）
    dummyHash = await argon2id({
      password: 'zpasswd-dummy-password',
      salt: 'zpasswd-dummy-sa',
      parallelism: 1,
      iterations: 2,
      memorySize: 65536,
      hashLength: 32,
      outputType: 'encoded',
    });
  }
  return dummyHash;
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
