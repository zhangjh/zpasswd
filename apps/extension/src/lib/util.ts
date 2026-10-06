/** base64 编解码（浏览器安全上下文可用，不依赖 Node Buffer） */
export function b64encode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** 常见二级 public suffix，用于 eTLD+1 近似计算 */
const TWO_LEVEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp',
  'com.au', 'net.au', 'org.au',
  'com.hk', 'org.hk', 'edu.hk',
  'com.tw', 'org.tw',
]);

/** 近似 eTLD+1：取末两段，命中二级后缀表则取末三段 */
export function etldPlusOne(host: string): string {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h) || h.includes(':') || !h.includes('.')) return h;
  const parts = h.split('.');
  const last2 = parts.slice(-2).join('.');
  if (TWO_LEVEL_SUFFIXES.has(last2) && parts.length >= 3) return parts.slice(-3).join('.');
  return last2;
}

export function etldPlusOneOfUrl(url: string): string | null {
  try {
    return etldPlusOne(new URL(url).hostname);
  } catch {
    return null;
  }
}

/** 下载文本文件（备份导出用） */
export function download(filename: string, text: string, mime = 'application/json'): void {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

/** 最小 CSV 解析器：处理引号包裹字段与转义引号 */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (c === '\r') {
      // skip
    } else {
      field += c;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.length > 0 && r.some((f) => f.trim() !== ''));
}

/** 复制到剪贴板并在 delayMs 后自动清除 */
export async function copyWithAutoClear(text: string, delayMs = 30000): Promise<void> {
  await navigator.clipboard.writeText(text);
  setTimeout(() => {
    navigator.clipboard.writeText('').catch(() => undefined);
  }, delayMs);
}
