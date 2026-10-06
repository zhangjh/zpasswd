import { describe, expect, it } from 'vitest';
import { decryptItem, encryptItem, unwrapDek, wrapDek } from '../src/envelope';
import { deriveMasterKey, deriveSubkey, randomKey, randomSalt } from '../src/kdf';

describe('envelope', () => {
  it('wraps/unwraps the DEK', async () => {
    const mk = await deriveMasterKey('pw', await randomSalt());
    const kek = await deriveSubkey(mk, 'enc');
    const dek = await randomKey();
    const box = await wrapDek(kek, dek);
    const back = await unwrapDek(kek, box);
    expect(Buffer.from(back).toString('hex')).toBe(Buffer.from(dek).toString('hex'));
  });

  it('refuses to unwrap with the wrong KEK', async () => {
    const mk = await deriveMasterKey('pw', await randomSalt());
    const kek = await deriveSubkey(mk, 'enc');
    const box = await wrapDek(kek, await randomKey());
    const wrongKek = await randomKey();
    await expect(unwrapDek(wrongKek, box)).rejects.toThrow();
  });

  it('encrypts/decrypts a vault item round-trip', async () => {
    const dek = await randomKey();
    const payload = JSON.stringify({ name: 'GitHub', username: 'zhangjh', password: 's3cret!', url: 'https://github.com' });
    const box = await encryptItem(dek, payload);
    expect(box.nonce).not.toBe(box.ciphertext);
    expect(await decryptItem(dek, box)).toBe(payload);
  });

  it('uses a fresh random nonce per encryption', async () => {
    const dek = await randomKey();
    const a = await encryptItem(dek, 'same');
    const b = await encryptItem(dek, 'same');
    expect(a.nonce).not.toBe(b.nonce);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it('detects tampering and wrong keys', async () => {
    const dek = await randomKey();
    const box = await encryptItem(dek, 'secret');
    const tampered = { ...box, ciphertext: box.ciphertext.slice(0, -4) + 'AAAA' };
    await expect(decryptItem(dek, tampered)).rejects.toThrow();
    await expect(decryptItem(await randomKey(), box)).rejects.toThrow();
  });
});
