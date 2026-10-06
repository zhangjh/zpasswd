import { describe, expect, it } from 'vitest';
import { deriveMasterKey, randomSalt } from '../src/kdf';
import { isValidMnemonic, recKeyFromMnemonic, recoveryMnemonicFromMasterKey } from '../src/recovery';

describe('recovery', () => {
  it('produces a deterministic 24-word mnemonic', async () => {
    const mk = await deriveMasterKey('pw', await randomSalt());
    const m1 = await recoveryMnemonicFromMasterKey(mk);
    const m2 = await recoveryMnemonicFromMasterKey(mk);
    expect(m1).toBe(m2);
    expect(m1.split(' ')).toHaveLength(24);
    expect(isValidMnemonic(m1)).toBe(true);
  });

  it('round-trips mnemonic -> rec key', async () => {
    const mk = await deriveMasterKey('pw', await randomSalt());
    const m = await recoveryMnemonicFromMasterKey(mk);
    const rec = recKeyFromMnemonic(m);
    expect(rec).toHaveLength(32);
  });

  it('rejects invalid mnemonics', () => {
    expect(() => recKeyFromMnemonic('abandon '.repeat(23) + 'aboutx')).toThrow();
    expect(isValidMnemonic('not a mnemonic')).toBe(false);
  });
});
