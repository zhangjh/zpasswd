/**
 * zpasswd 同步服务入口（Cloudflare Workers）。
 * Hono app，D1 绑定为 DB，JWT 密钥走 secret JWT_SECRET。
 */
import { Hono } from 'hono';
import type { App, Env } from './auth';
import { registerRoutes } from './routes';

const app: App = new Hono<{ Bindings: Env; Variables: { userId: string } }>();

app.get('/health', (c) => c.json({ ok: true, service: 'zpasswd-server' }));

registerRoutes(app);

// 未匹配路由：统一 404，不泄露路径信息
app.notFound((c) => c.json({ error: 'not found' }, 404));

export default app;
