import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from 'bip39';
import { deriveSubkey } from './kdf';

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * 恢复码：deriveSubkey(MK, "rec") -> 256bit -> BIP39 24 词，纸质保存。
 * 丢主密码 + 丢恢复码 = 数据永久丢失（零知识的代价）。
 * 恢复流程：24 词 -> 256bit rec 密钥 -> 直接派生 enc/auth 子密钥重建。
 *
 * 注意：本文件不使用 Node Buffer，保证浏览器/扩展/ServiceWorker 可运行。
 */
export async function recoveryMnemonicFromMasterKey(masterKey: Uint8Array): Promise<string> {
  const recKey = await deriveSubkey(masterKey, 'rec');
  // bip39 的类型声明要求 Buffer，但运行时 Uint8Array 完全可用（浏览器无 Buffer）
  return entropyToMnemonic(recKey as unknown as Buffer);
}

/** 24 词 -> 256bit rec 密钥。 */
export function recKeyFromMnemonic(mnemonic: string): Uint8Array {
  const normalized = mnemonic.trim().toLowerCase().split(/\s+/).join(' ');
  if (!validateMnemonic(normalized)) throw new Error('invalid recovery mnemonic');
  return hexToBytes(mnemonicToEntropy(normalized));
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic.trim().toLowerCase().split(/\s+/).join(' '));
}

export { bytesToHex, hexToBytes };
