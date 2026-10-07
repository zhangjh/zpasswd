import { bg } from './lib/messages';
import type { Credential } from './lib/types';

// 跨域 iframe 直接退出：不读取、不填充，防止钓鱼页嵌套。
// 注意：跨域时访问 window.top.location 本身就会抛异常，统一视为不可信。
const IS_TOP_OR_SAME_ORIGIN_FRAME: boolean = (() => {
  const top = window.top;
  try {
    if (top === null || top === window.self) return top === window.self;
    return top.location.origin === window.location.origin;
  } catch {
    return false;
  }
})();

if (IS_TOP_OR_SAME_ORIGIN_FRAME) {
  init();
}

function isVisible(el: HTMLElement): boolean {
  const r = el.getBoundingClientRect();
  const cs = getComputedStyle(el);
  return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none';
}

/** 找到密码框所在表单的用户名输入框 */
function findUsernameField(passwordField: HTMLInputElement): HTMLInputElement | null {
  const form = passwordField.form;
  const scope: ParentNode = form ?? passwordField.getRootNode() as ParentNode;
  const candidates = Array.from(
    scope.querySelectorAll<HTMLInputElement>(
      'input[type="text"], input[type="email"], input:not([type])',
    ),
  ).filter((el) => el !== passwordField && isVisible(el) && !el.readOnly && !el.disabled);
  // 优先取密码框之前的最后一个
  if (form) {
    const elements = Array.from(form.elements) as HTMLElement[];
    const pwIdx = elements.indexOf(passwordField);
    for (let i = pwIdx - 1; i >= 0; i--) {
      const el = elements[i];
      if (el instanceof HTMLInputElement && candidates.includes(el)) return el;
    }
  }
  return candidates[0] ?? null;
}

/** 用原生 setter 赋值并派发事件，兼容 React/Vue 受控组件 */
function setNativeValue(el: HTMLInputElement, value: string): void {
  const proto = HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
  if (setter) setter.call(el, value);
  else el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

let panelEl: HTMLElement | null = null;
let submitSeen = false;

/**
 * 同步抓取值并单发一条 RECORD_PENDING_SAVE（不 await）。
 * 解锁检查与去重由 background 统一做；页面可能正在卸载，单条消息尽力送达即可。
 */
function captureAndSend(pw: HTMLInputElement): void {
  const userField = findUsernameField(pw);
  bg({
    type: 'RECORD_PENDING_SAVE',
    entry: { url: window.location.href, username: userField?.value ?? '', password: pw.value },
  }).catch(() => {
    // 静默忽略（background 未就绪 / 页面卸载中）
  });
}

/** 用已知的最后一次值抓取（字段可能已从 DOM 移除） */
function captureWithKnownValue(pw: HTMLInputElement, password: string, username: string): void {
  bg({
    type: 'RECORD_PENDING_SAVE',
    entry: { url: window.location.href, username, password },
  }).catch(() => {
    // 静默忽略
  });
}

// SPA 登录检测：跟踪密码框的最后一次值；字段被移除或值被 JS 清空时视为一次登录提交。
// 覆盖无原生 submit、无页面跳转的 JS 登录（如 126 邮箱这类）。
const trackedPw = new Map<HTMLInputElement, { password: string; username: string }>();

function trackPasswordInput(e: Event): void {
  const t = e.target;
  if (!(t instanceof HTMLInputElement) || t.type !== 'password' || t.readOnly || t.disabled) return;
  if (t.value) {
    const userField = findUsernameField(t);
    trackedPw.set(t, { password: t.value, username: userField?.value ?? '' });
  } else {
    trackedPw.delete(t);
  }
}

function checkTrackedPasswords(): void {
  for (const [field, known] of trackedPw) {
    // 字段被移除，或值被 JS 清空/改掉 → 视为登录提交（submit 已处理过的跳过）
    if ((!field.isConnected || field.value !== known.password) && !submitSeen) {
      trackedPw.delete(field);
      // 用户名尽量取实时值（可能还在 DOM 里），取不到用跟踪到的
      let username = known.username;
      try {
        if (field.isConnected) username = findUsernameField(field)?.value ?? known.username;
      } catch {
        // ignore
      }
      captureWithKnownValue(field, known.password, username);
    } else if (!field.isConnected || field.value !== known.password) {
      // submit 已处理过，仅清理跟踪
      trackedPw.delete(field);
    }
  }
}

function closePanel(): void {
  panelEl?.remove();
  panelEl = null;
}

/** 在密码框旁用 Shadow DOM 渲染填充浮层（样式隔离，不被页面 CSS 污染） */
function showFillPanel(field: HTMLInputElement, creds: Credential[]): void {
  closePanel();
  const host = document.createElement('div');
  host.id = 'zpasswd-fill-host';
  const shadow = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = `
    .zp { position: fixed; z-index: 2147483647; background: #1a1a2e; color: #eee;
          border: 1px solid #444; border-radius: 8px; padding: 6px; font: 13px/1.4 system-ui, sans-serif;
          box-shadow: 0 4px 16px rgba(0,0,0,.4); min-width: 220px; }
    .zp-title { padding: 2px 6px 6px; color: #9fd; font-weight: 600; }
    .zp-item { display: flex; width: 100%; gap: 6px; align-items: center; padding: 6px; margin: 2px 0;
               background: #262640; color: #eee; border: 0; border-radius: 6px; cursor: pointer; text-align: left; }
    .zp-item:hover { background: #34345a; }
    .zp-x { position: absolute; top: 2px; right: 6px; background: none; border: 0; color: #888; cursor: pointer; }
  `;
  const box = document.createElement('div');
  box.className = 'zp';
  const rect = field.getBoundingClientRect();
  box.style.top = `${Math.min(rect.bottom + window.scrollY + 4, window.innerHeight - 160)}px`;
  box.style.left = `${Math.min(rect.left + window.scrollX, window.innerWidth - 240)}px`;

  const title = document.createElement('div');
  title.className = 'zp-title';
  title.textContent = `zpasswd：${creds.length} 个匹配的账号`;
  const x = document.createElement('button');
  x.className = 'zp-x';
  x.textContent = '✕';
  x.onclick = (e) => {
    e.stopPropagation();
    closePanel();
  };
  box.appendChild(title);
  box.appendChild(x);

  for (const c of creds.slice(0, 5)) {
    const btn = document.createElement('button');
    btn.className = 'zp-item';
    const label = c.username || '(无用户名)';
    btn.textContent = `🔑 ${label}`;
    btn.title = '点击填充';
    btn.onclick = (e) => {
      e.stopPropagation();
      fillCredential(field, c);
      closePanel();
    };
    box.appendChild(btn);
  }

  shadow.appendChild(style);
  shadow.appendChild(box);
  document.documentElement.appendChild(host);
  panelEl = host;

  setTimeout(() => {
    document.addEventListener('click', function dismiss(ev) {
      if (!host.contains(ev.target as Node)) {
        closePanel();
        document.removeEventListener('click', dismiss);
      }
    });
  }, 0);
  document.addEventListener(
    'keydown',
    function esc(ev) {
      if (ev.key === 'Escape') {
        closePanel();
        document.removeEventListener('keydown', esc);
      }
    },
    { once: true },
  );
}

function fillCredential(field: HTMLInputElement, cred: Credential): void {
  const userField = findUsernameField(field);
  if (userField && cred.username) setNativeValue(userField, cred.username);
  setNativeValue(field, cred.password);
  field.focus();
}

function init(): void {
  // 密码框聚焦 → 查询匹配凭证
  document.addEventListener('focusin', async (e) => {
    const t = e.target as HTMLElement;
    if (!(t instanceof HTMLInputElement) || t.type !== 'password' || t.readOnly || t.disabled) return;
    if (!isVisible(t)) return;
    try {
      const res = await bg<{ locked: boolean; credentials: Credential[] }>({
        type: 'GET_CREDENTIALS',
        url: window.location.href,
      });
      if (res.locked || res.credentials.length === 0) return;
      // 避免重复面板
      if (panelEl) closePanel();
      showFillPanel(t, res.credentials);
    } catch {
      // background 未就绪等情况静默忽略
    }
  });

  // 表单提交：传统表单与 React 受控表单（仍触发原生 submit）都能抓到。
  // 只做同步抓值 + 单条 fire-and-forget 消息，不在 content 端做解锁/去重判断
  // （background 统一处理），避免页面跳转中断多次异步往返导致记录丢失。
  document.addEventListener(
    'submit',
    (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;
      const pw = form.querySelector<HTMLInputElement>('input[type="password"]');
      if (!pw || !pw.value) return;
      submitSeen = true;
      captureAndSend(pw);
    },
    true,
  );

  // SPA 兜底：无原生 submit 的登录（如 div 拼的表单 + fetch 提交）在页面卸载时抓一次。
  // submit 已处理过的跳过，避免重复记录。
  window.addEventListener('pagehide', () => {
    if (submitSeen) return;
    const pw = document.querySelector<HTMLInputElement>('input[type="password"]');
    if (!pw || !pw.value || !isVisible(pw)) return;
    captureAndSend(pw);
  });

  // SPA 无跳转登录：密码框被移除或值被 JS 清空时，视为一次登录提交。
  // （如 126 邮箱：JS 提交、无原生 submit、无页面跳转）
  document.addEventListener('input', trackPasswordInput, true);
  const pwObserver = new MutationObserver(() => {
    try {
      checkTrackedPasswords();
    } catch {
      // 忽略
    }
  });
  pwObserver.observe(document.documentElement, { childList: true, subtree: true });
}
