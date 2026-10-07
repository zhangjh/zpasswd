import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './src/manifest';

// libsodium-wrappers-sumo@0.7.16 的 ESM dist 缺文件，走 CJS 构建（绝对路径绕过 exports 限制）
// 经 @pm/crypto 解析（pnpm 下 extension 自身 node_modules 里没有直连的 sodium 包）
const require = createRequire(import.meta.url);
const cryptoPkgDir = join(dirname(require.resolve('@pm/crypto')), '..');
const sodiumPkgDir = join(cryptoPkgDir, 'node_modules', 'libsodium-wrappers-sumo');

export default defineConfig({
  plugins: [crx({ manifest })],
  resolve: {
    alias: {
      'libsodium-wrappers-sumo': join(sodiumPkgDir, 'dist/modules-sumo/libsodium-wrappers.js'),
    },
  },
});
