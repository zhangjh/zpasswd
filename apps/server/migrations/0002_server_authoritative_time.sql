-- 时间基准收回服务端（配合 src/routes.ts 的改动）。
--
-- 背景：此前 vault_items.updated_at 采信客户端传来的 updatedAt，而增量同步游标
-- （/v1/sync 的 serverTime）用的是服务端时钟。两者不同源时：
--   * 客户端时钟慢于服务端 → 它写入的行"落在游标的过去"，其他设备永久漏拉；
--   * 客户端时钟快于服务端 → 该行的 updated_at 永远大于游标，每一轮同步都被
--     重复投递（客户端按 version 幂等，不会写错，但白白浪费流量）。
--
-- 代码侧已改为写入时一律用服务端时钟盖章。本迁移只做一件事：把历史上被
-- "未来时钟"写歪的行夹回当前时间，消掉上面第二种情况。
--
-- 幂等：只影响 updated_at 严格大于当前时间的行，可重复执行。

UPDATE vault_items
   SET updated_at = CAST(strftime('%s','now') AS INTEGER) * 1000
 WHERE updated_at > CAST(strftime('%s','now') AS INTEGER) * 1000;
