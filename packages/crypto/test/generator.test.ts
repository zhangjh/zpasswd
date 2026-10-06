import { describe, expect, it } from 'vitest';
import { generatePassword } from '../src/generator';

const UPPER_RE = /[A-Z]/;
const LOWER_RE = /[a-z]/;
const DIGIT_RE = /[0-9]/;
const SYMBOL_RE = /[^A-Za-z0-9]/;
const SIMILAR_RE = /[0O1lI|`]/;

describe('generator', () => {
  it('generates the requested length with all charsets represented', async () => {
    const { password, entropyBits, charsetSize } = await generatePassword({ length: 24 });
    expect(password).toHaveLength(24);
    expect(password).toMatch(UPPER_RE);
    expect(password).toMatch(LOWER_RE);
    expect(password).toMatch(DIGIT_RE);
    expect(password).toMatch(SYMBOL_RE);
    expect(password).not.toMatch(SIMILAR_RE);
    // entropy = 24 * log2(charsetSize)
    expect(entropyBits).toBeCloseTo(24 * Math.log2(charsetSize), 1);
    expect(entropyBits).toBeGreaterThan(128);
  });

  it('defaults to >= 128 bits of entropy', async () => {
    const { entropyBits } = await generatePassword();
    expect(entropyBits).toBeGreaterThanOrEqual(128);
  });

  it('respects custom options', async () => {
    const { password } = await generatePassword({ length: 12, symbols: false, uppercase: false });
    expect(password).toHaveLength(12);
    expect(password).not.toMatch(SYMBOL_RE);
    expect(password).not.toMatch(UPPER_RE);
    expect(password).toMatch(LOWER_RE);
    expect(password).toMatch(DIGIT_RE);
  });

  it('produces unique passwords', async () => {
    const set = new Set<string>();
    for (let i = 0; i < 50; i++) set.add((await generatePassword()).password);
    expect(set.size).toBe(50);
  });

  it('rejects bad lengths', async () => {
    await expect(generatePassword({ length: 4 })).rejects.toThrow();
    await expect(generatePassword({ length: 200 })).rejects.toThrow();
  });

  it('has roughly uniform character distribution (chi-square sanity)', async () => {
    // 200k chars over ~80-symbol charset: each symbol ~2500 expected; allow wide band
    const { password } = await generatePassword({ length: 128 });
    const counts = new Map<string, number>();
    for (let i = 0; i < 1500; i++) {
      const p = (await generatePassword({ length: 128 })).password;
      for (const c of p) counts.set(c, (counts.get(c) ?? 0) + 1);
    }
    void password;
    const vals = [...counts.values()];
    const mean = vals.reduce((a, b) => a + b, 0) / vals.length;
    for (const v of vals) {
      expect(v).toBeGreaterThan(mean * 0.5);
      expect(v).toBeLessThan(mean * 1.5);
    }
  }, 60000);
});
