import React, { useCallback, useEffect, useRef, useState } from 'react';
import { bg, type Status } from '../lib/messages';
import type { ItemMeta, PendingSave, VaultItemPlain } from '../lib/types';
import { copyWithAutoClear } from '../lib/util';
import { totpNow } from '../lib/totp';

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [err, setErr] = useState('');
  const refresh = useCallback(async () => {
    try {
      setStatus(await bg<Status>({ type: 'GET_STATUS' }));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    void refresh();
  }, [refresh]);

  if (err) return <div className="err">加载失败：{err}</div>;
  if (!status) return <div className="hint">加载中…</div>;
  if (!status.hasVault) return <CreateVault onDone={refresh} />;
  if (!status.unlocked) return <Unlock onDone={refresh} />;
  return <VaultView status={status} onStatusChange={refresh} />;
}

/* ---------------- 创建 vault ---------------- */

function CreateVault({ onDone }: { onDone: () => void }) {
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setErr('');
    if (pw.length < 8) {
      setErr('主密码至少 8 位，建议 12 位以上');
      return;
    }
    if (pw !== pw2) {
      setErr('两次输入不一致');
      return;
    }
    setBusy(true);
    try {
      await bg({ type: 'CREATE_VAULT', password: pw });
      setPw('');
      setPw2('');
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h2>🔐 zpasswd</h2>
      <p className="hint">
        首次使用：设置主密码。主密码只用于本地派生密钥，永不上传、
        永不存储明文。忘记主密码且无恢复码 = 数据永久丢失。
      </p>
      <label className="f">主密码</label>
      <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />
      <label className="f">确认主密码</label>
      <input
        type="password"
        value={pw2}
        onChange={(e) => setPw2(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && void submit()}
      />
      {err && <div className="err">{err}</div>}
      <button onClick={() => void submit()} disabled={busy} style={{ marginTop: 8, width: '100%' }}>
        {busy ? '正在派生密钥（约 1 秒）…' : '创建本地 vault'}
      </button>
    </div>
  );
}

/* ---------------- 解锁 ---------------- */

function Unlock({ onDone }: { onDone: () => void }) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setErr('');
    setBusy(true);
    try {
      await bg({ type: 'UNLOCK', password: pw });
      setPw('');
      onDone();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h2>🔐 zpasswd</h2>
      <label className="f">主密码</label>
      <input
        type="password"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && void submit()}
        autoFocus
      />
      {err && <div className="err">{err}</div>}
      <button onClick={() => void submit()} disabled={busy} style={{ marginTop: 8, width: '100%' }}>
        {busy ? '正在派生密钥…' : '解锁'}
      </button>
    </div>
  );
}

/* ---------------- 主界面 ---------------- */

function VaultView({ status, onStatusChange }: { status: Status; onStatusChange: () => void }) {
  const [items, setItems] = useState<ItemMeta[]>([]);
  const [query, setQuery] = useState('');
  const [showAdd, setShowAdd] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [viewingId, setViewingId] = useState<string | null>(null);
  const [msg, setMsg] = useState('');
  const [pending, setPending] = useState(status.pendingSave);
  const timer = useRef<number | null>(null);

  const load = useCallback(async (q: string) => {
    setItems(await bg<ItemMeta[]>({ type: 'LIST_ITEMS', query: q }));
  }, []);

  useEffect(() => {
    if (timer.current) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      void load(query).catch(() => undefined);
    }, 200);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [query, load]);

  useEffect(() => {
    void load('').catch(() => undefined);
  }, [load]);

  const doLock = async () => {
    await bg({ type: 'LOCK' });
    onStatusChange();
  };

  const doSync = async () => {
    setMsg('同步中…');
    try {
      const r = await bg<{ skipped?: boolean; pushed: number; pulled: number; conflicts: number }>({
        type: 'SYNC_NOW',
      });
      setMsg(
        r.skipped
          ? '未配置同步服务（纯本地模式）'
          : `同步完成：推送 ${r.pushed} / 拉取 ${r.pulled}` +
            (r.conflicts ? ` / 冲突 ${r.conflicts} 条已移入「同步冲突」` : ''),
      );
      void load(query);
      onStatusChange();
    } catch (e) {
      setMsg(`同步失败：${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const del = async (id: string, name: string) => {
    if (!window.confirm(`删除「${name}」？（软删除，可同步到其他设备）`)) return;
    await bg({ type: 'DELETE_ITEM', id });
    void load(query);
  };

  const toggleFav = async (id: string) => {
    await bg({ type: 'TOGGLE_FAVORITE', id });
    void load(query);
  };

  const savePending = async () => {
    const p = await bg<PendingSave | null>({ type: 'CONSUME_PENDING_SAVE' });
    setPending(null);
    if (!p) return;
    let site = p.url;
    try {
      site = new URL(p.url).hostname;
    } catch {
      // keep raw
    }
    await bg({
      type: 'ADD_ITEM',
      item: { name: site, username: p.username, password: p.password, url: p.url, notes: '', totpSeed: '' },
    });
    setMsg('已保存新登录信息');
    void load(query);
    onStatusChange();
  };

  const dismissPending = async () => {
    await bg({ type: 'DISMISS_PENDING_SAVE' });
    setPending(null);
    onStatusChange();
  };

  return (
    <div>
      <div className="toolbar">
        <input placeholder="搜索名称 / 用户名 / 网址…" value={query} onChange={(e) => setQuery(e.target.value)} />
        <button className="ghost fit" title="新增" onClick={() => setShowAdd(true)}>
          ＋
        </button>
      </div>

      {pending && (
        <div className="banner">
          <div>
            检测到新登录：<b>{pending.url}</b>
            {pending.username ? ` / ${pending.username}` : ''}
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            <button className="small" onClick={() => void savePending()}>
              保存到 vault
            </button>
            <button className="small ghost" onClick={() => void dismissPending()}>
              忽略
            </button>
          </div>
        </div>
      )}

      {msg && <div className="hint">{msg}</div>}

      {items.length === 0 && <div className="hint">没有条目，点右上角 ＋ 添加，或在网页登录后自动提示保存。</div>}

      {items.map((it) => (
        <div className="item" key={it.id}>
          <div className="row">
            <div>
              <div className="name">{it.name || '(未命名)'}</div>
              <div className="sub">{it.username}{it.url ? ` · ${it.url}` : ''}</div>
            </div>
            <button
              className={`star fit ${it.favorite ? 'on' : ''}`}
              title="收藏"
              onClick={() => void toggleFav(it.id)}
            >
              ★
            </button>
          </div>
          <div className="actions">
            <button className="small ghost" onClick={() => void copyWithAutoClear(it.username)}>
              复制用户
            </button>
            <button
              className="small ghost"
              onClick={async () => {
                const full = await bg<{ plain: VaultItemPlain }>({ type: 'GET_ITEM', id: it.id });
                await copyWithAutoClear(full.plain.password);
                setMsg('密码已复制，30 秒后自动清除剪贴板');
              }}
            >
              复制密码
            </button>
            <button className="small ghost" onClick={() => setViewingId(it.id)}>
              详情
            </button>
            <button
              className="small danger"
              onClick={() => void del(it.id, it.name)}
            >
              删除
            </button>
          </div>
        </div>
      ))}

      <div className="footer">
        <span className="hint">{status.syncConfigured ? `已连接同步${status.syncEmail ? ` · ${status.syncEmail}` : ''}` : '纯本地模式'}</span>
        <span className="row fit" style={{ gap: 6 }}>
          <button className="small ghost" onClick={() => void doSync()}>
            同步
          </button>
          <button className="small ghost" onClick={() => chrome.runtime.openOptionsPage()}>
            设置
          </button>
          <button className="small ghost" onClick={() => void doLock()}>
            锁定
          </button>
        </span>
      </div>

      {showAdd && (
        <Modal onClose={() => setShowAdd(false)}>
          <h3>新增条目</h3>
          <ItemForm
            onSave={async (plain) => {
              await bg({ type: 'ADD_ITEM', item: plain });
              setShowAdd(false);
              void load(query);
            }}
            onCancel={() => setShowAdd(false)}
          />
        </Modal>
      )}

      {editingId && (
        <EditModal
          id={editingId}
          onClose={() => setEditingId(null)}
          onSaved={() => {
            setEditingId(null);
            setViewingId(null);
            void load(query);
          }}
        />
      )}

      {viewingId && !editingId && (
        <ViewModal
          id={viewingId}
          onClose={() => setViewingId(null)}
          onEdit={() => setEditingId(viewingId)}
        />
      )}
    </div>
  );
}

/* ---------------- 通用组件 ---------------- */

function Modal({ children, onClose }: { children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}

function PasswordInput({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  const [bits, setBits] = useState<number | null>(null);
  const [len, setLen] = useState(24);

  const gen = async () => {
    const r = await bg<{ password: string; entropyBits: number }>({
      type: 'GENERATE',
      opts: { length: len },
    });
    onChange(r.password);
    setBits(r.entropyBits);
  };

  return (
    <div>
      <div className="row">
        <input type="text" value={value} onChange={(e) => onChange(e.target.value)} autoComplete="off" />
        <select
          className="fit"
          value={len}
          onChange={(e) => setLen(Number(e.target.value))}
          title="生成长度"
          style={{ width: 64 }}
        >
          {[16, 20, 24, 32].map((n) => (
            <option key={n} value={n}>
              {n} 位
            </option>
          ))}
        </select>
        <button type="button" className="ghost fit" onClick={() => void gen()}>
          生成
        </button>
      </div>
      {bits !== null && (
        <span className={`gen-entropy ${bits >= 128 ? 'good' : 'warn'}`}>
          熵约 {bits} bit{bits < 128 ? '（偏低，建议加长）' : ''}
        </span>
      )}
    </div>
  );
}

function ItemForm({
  initial,
  onSave,
  onCancel,
}: {
  initial?: VaultItemPlain;
  onSave: (plain: VaultItemPlain) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initial?.name ?? '');
  const [username, setUsername] = useState(initial?.username ?? '');
  const [password, setPassword] = useState(initial?.password ?? '');
  const [url, setUrl] = useState(initial?.url ?? '');
  const [notes, setNotes] = useState(initial?.notes ?? '');
  const [totpSeed, setTotpSeed] = useState(initial?.totpSeed ?? '');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setErr('');
    if (!name.trim()) {
      setErr('名称不能为空');
      return;
    }
    setBusy(true);
    try {
      await onSave({
        name: name.trim(),
        username: username.trim(),
        password,
        url: url.trim(),
        notes,
        totpSeed: totpSeed.trim().replace(/\s+/g, ''),
        customFields: initial?.customFields,
      });
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <label className="f">名称 *</label>
      <input type="text" value={name} onChange={(e) => setName(e.target.value)} />
      <label className="f">用户名</label>
      <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
      <label className="f">密码</label>
      <PasswordInput value={password} onChange={setPassword} />
      <label className="f">网址</label>
      <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" autoComplete="off" />
      <label className="f">TOTP 密钥（可选，base32）</label>
      <input type="text" value={totpSeed} onChange={(e) => setTotpSeed(e.target.value)} autoComplete="off" />
      <label className="f">备注</label>
      <textarea value={notes} onChange={(e) => setNotes(e.target.value)} />
      {err && <div className="err">{err}</div>}
      <div className="row" style={{ marginTop: 10 }}>
        <button onClick={() => void submit()} disabled={busy}>
          保存
        </button>
        <button className="ghost" onClick={onCancel}>
          取消
        </button>
      </div>
    </div>
  );
}

function EditModal({ id, onClose, onSaved }: { id: string; onClose: () => void; onSaved: () => void }) {
  const [plain, setPlain] = useState<VaultItemPlain | null>(null);
  useEffect(() => {
    void bg<{ plain: VaultItemPlain }>({ type: 'GET_ITEM', id }).then((r) => setPlain(r.plain));
  }, [id]);
  return (
    <Modal onClose={onClose}>
      <h3>编辑条目</h3>
      {!plain ? (
        <div className="hint">加载中…</div>
      ) : (
        <ItemForm
          initial={plain}
          onCancel={onClose}
          onSave={async (p) => {
            await bg({ type: 'UPDATE_ITEM', id, item: p });
            onSaved();
          }}
        />
      )}
    </Modal>
  );
}

function TotpCode({ seed }: { seed: string }) {
  const [t, setT] = useState<{ code: string; secondsLeft: number } | null>(() => {
    try {
      return totpNow(seed);
    } catch {
      return null;
    }
  });
  useEffect(() => {
    const timer = window.setInterval(() => {
      try {
        setT(totpNow(seed));
      } catch {
        setT(null);
      }
    }, 1000);
    return () => window.clearInterval(timer);
  }, [seed]);
  if (!t) return <span className="hint">TOTP 密钥无效</span>;
  return (
    <span>
      <span className="totp">{t.code}</span> <span className="hint">{t.secondsLeft}s 后刷新</span>{' '}
      <button className="small ghost" onClick={() => void copyWithAutoClear(t.code)}>
        复制
      </button>
    </span>
  );
}

function ViewModal({ id, onClose, onEdit }: { id: string; onClose: () => void; onEdit: () => void }) {
  const [plain, setPlain] = useState<VaultItemPlain | null>(null);
  const [showPw, setShowPw] = useState(false);
  useEffect(() => {
    void bg<{ plain: VaultItemPlain }>({ type: 'GET_ITEM', id }).then((r) => setPlain(r.plain));
  }, [id]);
  return (
    <Modal onClose={onClose}>
      <h3>条目详情</h3>
      {!plain ? (
        <div className="hint">加载中…</div>
      ) : (
        <div>
          <Field k="名称" v={plain.name} />
          <Field k="用户名" v={plain.username} copyable />
          <div>
            <span className="hint">密码：</span>{' '}
            <span className="mono">{showPw ? plain.password : '••••••••'}</span>{' '}
            <button className="small ghost" onClick={() => setShowPw(!showPw)}>
              {showPw ? '隐藏' : '显示'}
            </button>{' '}
            <button className="small ghost" onClick={() => void copyWithAutoClear(plain.password)}>
              复制
            </button>
          </div>
          {plain.url && <Field k="网址" v={plain.url} copyable />}
          {plain.totpSeed && (
            <div style={{ marginTop: 6 }}>
              <span className="hint">TOTP：</span>
              <TotpCode seed={plain.totpSeed} />
            </div>
          )}
          {plain.notes && <Field k="备注" v={plain.notes} />}
          <div className="row" style={{ marginTop: 10 }}>
            <button onClick={onEdit}>编辑</button>
            <button className="ghost" onClick={onClose}>
              关闭
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

function Field({ k, v, copyable }: { k: string; v: string; copyable?: boolean }) {
  if (!v) return null;
  return (
    <div style={{ marginTop: 4 }}>
      <span className="hint">{k}：</span> <span className="mono">{v}</span>{' '}
      {copyable && (
        <button className="small ghost" onClick={() => void copyWithAutoClear(v)}>
          复制
        </button>
      )}
    </div>
  );
}
