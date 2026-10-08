import { wordlists } from 'bip39';
import sodium from 'libsodium-wrappers-sumo';
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

// 只取 bip39 的英文词表数据（纯数据，不触发它的 Buffer 代码路径）。
const WORDLIST: readonly string[] = wordlists.english;
const WORD_INDEX = new Map<string, number>(WORDLIST.map((w, i) => [w, i]));

function bytesToBits(bytes: Uint8Array): string {
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  return bits;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.crypto_hash_sha256(data);
}

/**
 * BIP39：32 字节熵 -> 24 个英文助记词。
 * 自己实现而不调用 bip39 的 entropyToMnemonic：后者在运行时调 Buffer.from，
 * 浏览器/扩展/ServiceWorker 里没有 Buffer 会报 "Buffer is not defined"。
 */
export async function entropyToMnemonic(entropy: Uint8Array): Promise<string> {
  if (entropy.length !== 32) throw new Error('entropy must be 32 bytes');
  const hash = await sha256(entropy);
  const bits = bytesToBits(entropy) + bytesToBits(hash).slice(0, 8); // 256 + 8 校验位
  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    words.push(WORDLIST[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]);
  }
  return words.join(' ');
}

/** 24 词 -> 32 字节熵（含校验和验证，词不在表或校验失败抛异常）。 */
export async function mnemonicToEntropy(mnemonic: string): Promise<Uint8Array> {
  const words = mnemonic.trim().toLowerCase().split(/\s+/);
  if (words.length !== 24) throw new Error('mnemonic must be 24 words');
  let bits = '';
  for (const w of words) {
    const idx = WORD_INDEX.get(w);
    if (idx === undefined) throw new Error(`unknown word: ${w}`);
    bits += idx.toString(2).padStart(11, '0');
  }
  const entropy = new Uint8Array(32);
  const entropyBits = bits.slice(0, 256);
  for (let i = 0; i < 32; i++) entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  const hash = await sha256(entropy);
  if (bytesToBits(hash).slice(0, 8) !== bits.slice(256)) throw new Error('invalid checksum');
  return entropy;
}

export async function validateMnemonic(mnemonic: string): Promise<boolean> {
  try {
    await mnemonicToEntropy(mnemonic);
    return true;
  } catch {
    return false;
  }
}

/**
 * 恢复码：deriveSubkey(MK, "rec") -> 256bit -> BIP39 24 词，纸质保存。
 * 丢主密码 + 丢恢复码 = 数据永久丢失（零知识的代价）。
 * 恢复流程：24 词 -> 256bit rec 密钥 -> 直接派生 enc/auth 子密钥重建。
 */
export async function recoveryMnemonicFromMasterKey(masterKey: Uint8Array): Promise<string> {
  const recKey = await deriveSubkey(masterKey, 'rec');
  return entropyToMnemonic(recKey);
}

/** 24 词 -> 256bit rec 密钥。 */
export async function recKeyFromMnemonic(mnemonic: string): Promise<Uint8Array> {
  return mnemonicToEntropy(mnemonic.trim().toLowerCase().split(/\s+/).join(' '));
}

export async function isValidMnemonic(mnemonic: string): Promise<boolean> {
  return validateMnemonic(mnemonic.trim().toLowerCase().split(/\s+/).join(' '));
}

export { bytesToHex, hexToBytes };
