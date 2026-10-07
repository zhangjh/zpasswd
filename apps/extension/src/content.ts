import { bg } from './lib/messages';
import type { Credential } from './lib/types';

// 跨域 iframe 策略：
// - 填充（FILL）：只在顶层或同源 frame 跑，防止钓鱼页嵌套时误填。
// - 保存检测（SAVE）：所有 frame 都跑，用各自 frame 自己的 URL 记录
//   （如 126 邮箱登录框在 iframe 里；用 iframe 自身 URL 关联凭证是安全的，
//   不会把凭证记到顶层页面名下）。
const IS_TOP_OR_SAME_ORIGIN_FRAME: boolean = (() => {
  const top = window.top;
  try {
    if (top === null || top === window.self) return top === window.self;
    return top.location.origin === window.location.origin;
  } catch {
    return false;
  }
})();

init();

function init(): void {
  initSaveDetection(); // 所有 frame 都跑保存检测
  if (IS_TOP_OR_SAME_ORIGIN_FRAME) {
    initFill(); // 填充只在顶层/同源跑
  }
  // 顶层 frame：接收来自 iframe 的保存确认框显示请求
  if (window.self === window.top) {
    chrome.runtime.onMessage.addListener((msg: unknown) => {
      if (
        typeof msg === 'object' && msg !== null &&
        (msg as { type?: string }).type === 'SHOW_SAVE_PROMPT'
      ) {
        showSavePrompt((msg as { username?: string }).username ?? '');
      }
    });
  }
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

/** 用已知的最后一次值抓取（字段可能已从 DOM 移除）；SPA 页内场景会再弹确认框 */
function captureWithKnownValue(
  pw: HTMLInputElement,
  password: string,
  username: string,
  showPrompt: boolean,
): void {
  bg({
    type: 'RECORD_PENDING_SAVE',
    entry: { url: window.location.href, username, password },
    // 页内弹确认框时不再发系统通知，避免双重打扰
    quiet: showPrompt,
  })
    .then(() => {
      if (showPrompt) showSavePrompt(username);
    })
    .catch(() => {
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
      // SPA 页内场景：记录后弹确认框（页面没跳转，用户正看着）。
      // 跨域 iframe 里不直接弹（看不见），转由顶层 frame 显示。
      const isTop = (() => {
        try {
          return window.self === window.top;
        } catch {
          return false;
        }
      })();
      if (isTop) {
        captureWithKnownValue(field, known.password, username, true);
      } else {
        bg({
          type: 'RECORD_PENDING_SAVE',
          entry: { url: window.location.href, username, password: known.password },
          quiet: true,
        })
          .then(() => bg({ type: 'SHOW_SAVE_PROMPT', username }))
          .catch(() => undefined);
      }
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

let savePromptEl: HTMLElement | null = null;

function closeSavePrompt(): void {
  savePromptEl?.remove();
  savePromptEl = null;
}

/** SPA 页内保存确认框：右上角浮层，Shadow DOM 样式隔离 */
function showSavePrompt(username: string): void {
  closeSavePrompt();
  const host = document.createElement('div');
  host.id = 'zpasswd-save-host';
  const shadow = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = `
    .zp-save { position: fixed; z-index: 2147483647; top: 16px; right: 16px;
               background: #1a1a2e; color: #eee; border: 1px solid #4a4ae0; border-radius: 10px;
               padding: 12px 14px; font: 13px/1.5 system-ui, sans-serif;
               box-shadow: 0 6px 24px rgba(0,0,0,.5); max-width: 300px; }
    .zp-save .t { font-weight: 600; margin-bottom: 4px; }
    .zp-save .u { color: #9fd; margin-bottom: 8px; word-break: break-all; }
    .zp-save .row { display: flex; gap: 8px; justify-content: flex-end; }
    .zp-save button { padding: 6px 14px; border: 0; border-radius: 6px; cursor: pointer; font-size: 13px; }
    .zp-save .ok { background: #4a4ae0; color: #fff; }
    .zp-save .ok:hover { background: #5a5af0; }
    .zp-save .no { background: #2a2a40; color: #ccc; }
    .zp-save .no:hover { background: #34345a; }
    .zp-save .done { color: #9fd; }
  `;
  const box = document.createElement('div');
  box.className = 'zp-save';

  const title = document.createElement('div');
  title.className = 't';
  title.textContent = 'zpasswd：检测到新登录';
  const user = document.createElement('div');
  user.className = 'u';
  user.textContent = username ? `账号：${username}` : '是否保存到保险库？';
  const row = document.createElement('div');
  row.className = 'row';

  const btnOk = document.createElement('button');
  btnOk.className = 'ok';
  btnOk.textContent = '保存';
  btnOk.onclick = async (e) => {
    e.stopPropagation();
    btnOk.textContent = '保存中…';
    try {
      await bg({ type: 'CONFIRM_PENDING_SAVE' });
      box.innerHTML = '';
      const done = document.createElement('div');
      done.className = 'done';
      done.textContent = '✓ 已保存到保险库';
      box.appendChild(done);
      setTimeout(closeSavePrompt, 1500);
    } catch {
      btnOk.textContent = '保存失败，请在扩展弹窗中保存';
    }
  };
  const btnNo = document.createElement('button');
  btnNo.className = 'no';
  btnNo.textContent = '忽略';
  btnNo.onclick = (e) => {
    e.stopPropagation();
    bg({ type: 'DISMISS_PENDING_SAVE' }).catch(() => undefined);
    closeSavePrompt();
  };
  row.appendChild(btnNo);
  row.appendChild(btnOk);
  box.appendChild(title);
  box.appendChild(user);
  box.appendChild(row);

  shadow.appendChild(style);
  shadow.appendChild(box);
  document.documentElement.appendChild(host);
  savePromptEl = host;

  // 10 秒无操作自动收起（待保存仍在，可通过角标/弹窗补救）
  setTimeout(() => {
    if (savePromptEl === host) closeSavePrompt();
  }, 10000);
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

/** 填充：密码框聚焦 → 查询匹配凭证并弹浮层（仅顶层/同源 frame） */
function initFill(): void {
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
}

/** 保存检测：所有 frame 都跑，用各自 frame 自己的 URL */
function initSaveDetection(): void {
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
