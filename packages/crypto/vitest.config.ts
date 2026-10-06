import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { defineConfig } from 'vitest/config';

// libsodium-wrappers@0.7.16 的 ESM dist 缺文件，走 CJS 构建（绝对路径绕过 exports 限制）
const require = createRequire(import.meta.url);
const mainFile = require.resolve('libsodium-wrappers-sumo'); // -> dist/... 下的入口
const pkgDir = join(dirname(mainFile), '..', '..');

export default defineConfig({
  resolve: {
    alias: {
      'libsodium-wrappers-sumo': join(pkgDir, 'dist/modules-sumo/libsodium-wrappers.js'),
    },
  },
});
