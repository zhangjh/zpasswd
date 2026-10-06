import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './src/manifest';

// libsodium-wrappers-sumo@0.7.16 的 ESM dist 缺文件，走 CJS 构建（绝对路径绕过 exports 限制）
const require = createRequire(import.meta.url);
const sodiumPkgDir = join(dirname(require.resolve('libsodium-wrappers-sumo')), '..', '..');

export default defineConfig({
  plugins: [crx({ manifest })],
  resolve: {
    alias: {
      'libsodium-wrappers-sumo': join(sodiumPkgDir, 'dist/modules-sumo/libsodium-wrappers.js'),
    },
  },
});
