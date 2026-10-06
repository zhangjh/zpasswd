import { describe, expect, it } from 'vitest';
import {
  KDF_MEMLIMIT,
  KDF_OPSLIMIT,
  deriveMasterKey,
  deriveSubkey,
  makeAuthVerifier,
  randomSalt,
  verifyAuthKey,
} from '../src/kdf';

describe('kdf', () => {
  it('freezes kdf params (changing them breaks cross-client compat)', () => {
    expect(KDF_OPSLIMIT).toBe(3);
    expect(KDF_MEMLIMIT).toBe(67_108_864);
  });

  it('derives a deterministic 32-byte master key', async () => {
    const salt = await randomSalt();
    const k1 = await deriveMasterKey('correct horse battery staple', salt);
    const k2 = await deriveMasterKey('correct horse battery staple', salt);
    expect(k1).toHaveLength(32);
    expect(Buffer.from(k1).toString('hex')).toBe(Buffer.from(k2).toString('hex'));
  });

  it('different salts / passwords give different keys', async () => {
    const s1 = await randomSalt();
    const s2 = await randomSalt();
    const a = await deriveMasterKey('pw', s1);
    const b = await deriveMasterKey('pw', s2);
    const c = await deriveMasterKey('pw2', s1);
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(b).toString('hex'));
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(c).toString('hex'));
  });

  it('rejects bad salt length', async () => {
    await expect(deriveMasterKey('pw', new Uint8Array(8))).rejects.toThrow();
  });

  it('derives isolated subkeys per purpose', async () => {
    const salt = await randomSalt();
    const mk = await deriveMasterKey('pw', salt);
    const enc = await deriveSubkey(mk, 'enc');
    const auth = await deriveSubkey(mk, 'auth');
    const rec = await deriveSubkey(mk, 'rec');
    const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
    expect(new Set([hex(enc), hex(auth), hex(rec)]).size).toBe(3);
    // deterministic
    expect(hex(await deriveSubkey(mk, 'enc'))).toBe(hex(enc));
  });

  it('auth verifier round-trips; wrong key fails', async () => {
    const salt = await randomSalt();
    const mk = await deriveMasterKey('pw', salt);
    const authKey = await deriveSubkey(mk, 'auth');
    const verifier = await makeAuthVerifier(authKey);
    expect(await verifyAuthKey(authKey, verifier)).toBe(true);
    const wrong = new Uint8Array(authKey);
    wrong[0] ^= 1;
    expect(await verifyAuthKey(wrong, verifier)).toBe(false);
  }, 20000);
});
