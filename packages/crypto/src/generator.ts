import sodium from 'libsodium-wrappers-sumo';

export interface GenerateOptions {
  length?: number; // 默认 24（80 字符集下约 152bit 熵，保底 ≥128bit）
  uppercase?: boolean; // 默认 true
  lowercase?: boolean; // 默认 true
  digits?: boolean; // 默认 true
  symbols?: boolean; // 默认 true
  excludeSimilar?: boolean; // 默认 true，剔除 0O1lI
}

export interface GeneratedPassword {
  password: string;
  /** 熵（bit）= length * log2(charsetSize)。<128 标黄提醒用户加长。 */
  entropyBits: number;
  charsetSize: number;
}

const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; // 已剔除 I,O（与 excludeSimilar 语义一致的基础集）
const LOWER = 'abcdefghijkmnopqrstuvwxyz'; // 已剔除 l
const DIGITS = '23456789'; // 已剔除 0,1
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?';
const SIMILAR_FULL = new Set(['0', 'O', 'o', '1', 'l', 'I', '|', '`']);

function buildCharset(o: Required<GenerateOptions>): string {
  let cs = '';
  if (o.uppercase) cs += UPPER;
  if (o.lowercase) cs += LOWER;
  if (o.digits) cs += DIGITS;
  if (o.symbols) cs += SYMBOLS;
  if (!o.excludeSimilar) {
    // 补回易混淆字符（仅当用户明确关闭剔除时）
    if (o.uppercase) cs += 'IO';
    if (o.lowercase) cs += 'lo';
    if (o.digits) cs += '01';
  }
  // 去重
  return [...new Set(cs)].filter((c) => o.excludeSimilar ? !SIMILAR_FULL.has(c) : true).join('');
}

/**
 * CSPRNG 密码生成。拒绝采样消除模偏差，保证每个字符均匀分布。
 * 至少保证每类启用的字符集各出现 1 个（避免 "20 个全是小写" 的尴尬）。
 */
export async function generatePassword(opts: GenerateOptions = {}): Promise<GeneratedPassword> {
  await sodium.ready;
  const o: Required<GenerateOptions> = {
    length: 24,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
    excludeSimilar: true,
    ...opts,
  };
  if (o.length < 8) throw new Error('password length must be >= 8');
  if (o.length > 128) throw new Error('password length must be <= 128');

  const charset = buildCharset(o);
  if (charset.length === 0) throw new Error('at least one charset must be enabled');
  const n = charset.length;

  // 拒绝采样上界：256 - (256 % n)，消除模偏差
  const limit = 256 - (256 % n);
  const pick = (): string => {
    for (;;) {
      const b = sodium.randombytes_buf(1)[0];
      if (b < limit) return charset[b % n];
    }
  };

  const chars: string[] = [];
  // 每类字符集至少 1 个
  const groups: string[] = [];
  if (o.uppercase) groups.push(UPPER);
  if (o.lowercase) groups.push(LOWER);
  if (o.digits) groups.push(DIGITS);
  if (o.symbols) groups.push(SYMBOLS);
  for (const g of groups) {
    const filtered = [...g].filter((c) => charset.includes(c)).join('');
    chars.push(filtered[sodium.randombytes_uniform(filtered.length)]);
  }
  while (chars.length < o.length) chars.push(pick());
  // Fisher-Yates 洗牌（CSPRNG 驱动）
  for (let i = chars.length - 1; i > 0; i--) {
    const j = sodium.randombytes_uniform(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  const password = chars.join('');
  const entropyBits = Math.round(o.length * Math.log2(n) * 10) / 10;
  return { password, entropyBits, charsetSize: n };
}
