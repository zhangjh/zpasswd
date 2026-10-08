import { defineManifest } from '@crxjs/vite-plugin';

export default defineManifest({
  manifest_version: 3,
  name: 'zpasswd',
  version: '0.1.4',
  description: '零知识密码管理器：生成、存储与自动填充，服务端只存密文',
  action: {
    default_popup: 'src/popup/index.html',
    default_title: 'zpasswd',
    default_icon: {
      16: 'icons/icon-16.png',
      32: 'icons/icon-32.png',
      48: 'icons/icon-48.png',
      128: 'icons/icon-128.png',
    },
  },
  icons: {
    16: 'icons/icon-16.png',
    48: 'icons/icon-48.png',
    128: 'icons/icon-128.png',
  },
  options_page: 'src/options/index.html',
  background: {
    service_worker: 'src/background.ts',
    type: 'module',
  },
  content_scripts: [
    {
      matches: ['<all_urls>'],
      js: ['src/content.ts'],
      // 登录框经常在 iframe 里（如 126 邮箱）：所有 frame 都注入，
      // 保存检测在各 frame 用自身 URL 跑，填充仍只在顶层/同源跑（content.ts 内控制）
      all_frames: true,
    },
  ],
  // storage: vault 身份与设置；alarms: 空闲自动锁定；idle 保留供将来精确检测
  // notifications: 锁定中检测到登录时提醒用户解锁保存
  permissions: ['storage', 'alarms', 'idle', 'notifications'],
  host_permissions: ['<all_urls>'],
  // libsodium 跑在 WebAssembly 上；MV3 默认 CSP（script-src 'self'）会拦截
  // WebAssembly.instantiate，必须显式放行 wasm-unsafe-eval（作用于扩展页与 SW）
  content_security_policy: {
    extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';",
  },
});
