import { hmac } from '@noble/hashes/hmac';
import { sha1 } from '@noble/hashes/sha1';

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** base32 解码（RFC 4648，约 20 行；不为这点功能引入大库） */
export function base32Decode(s: string): Uint8Array {
  const clean = s
    .trim()
    .replace(/=+$/, '')
    .toUpperCase()
    .replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export interface TotpResult {
  code: string;
  secondsLeft: number;
}

/** TOTP（RFC 6238 / SHA-1 / 30s / 6 位） */
export function totpNow(secretB32: string, digits = 6, period = 30): TotpResult {
  const key = base32Decode(secretB32);
  if (key.length === 0) throw new Error('TOTP seed 无效');
  const counter = Math.floor(Date.now() / 1000 / period);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter));
  const h = hmac(sha1, key, msg);
  const offset = h[h.length - 1] & 0x0f;
  const bin =
    ((h[offset] & 0x7f) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
  const code = (bin % 10 ** digits).toString().padStart(digits, '0');
  const secondsLeft = period - (Math.floor(Date.now() / 1000) % period);
  return { code, secondsLeft };
}
