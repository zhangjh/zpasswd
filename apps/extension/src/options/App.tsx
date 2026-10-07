import React, { useEffect, useState } from 'react';
import { bg, type Status } from '../lib/messages';
import { DEFAULT_SERVER_URL } from '../lib/sync';
import type { Settings, VaultItemPlain } from '../lib/types';
import { download, parseCsv } from '../lib/util';

export default function App() {
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    void bg<Status>({ type: 'GET_STATUS' }).then(setStatus).catch(() => undefined);
  }, []);

  return (
    <div style={{ maxWidth: 640, margin: '0 auto' }}>
      <h2>⚙️ zpasswd 设置</h2>
      {!status ? (
        <div className="hint">加载中…</div>
      ) : !status.unlocked ? (
        <div className="hint">请先点击浏览器工具栏的 zpasswd 图标解锁 vault，再回来设置。</div>
      ) : (
        <>
          <GeneralSettings />
          <SyncSettings onChanged={() => void bg<Status>({ type: 'GET_STATUS' }).then(setStatus)} />
          <BackupSection />
          <ImportSection />
          <RecoverySection />
          <DangerZone />
        </>
      )}
    </div>
  );
}

/* ---------------- 通用 ---------------- */

function GeneralSettings() {
  const [s, setS] = useState<Settings | null>(null);
  const [msg, setMsg] = useState('');
  useEffect(() => {
    void bg<Settings>({ type: 'GET_SETTINGS' }).then(setS);
  }, []);
  if (!s) return null;
  const save = async () => {
    await bg({ type: 'SAVE_SETTINGS', settings: s });
    setMsg('已保存');
    setTimeout(() => setMsg(''), 2000);
  };
  return (
    <section>
      <h3>通用</h3>
      <label className="f">空闲自动锁定（分钟）</label>
      <input
        type="number"
        min={1}
        max={120}
        value={s.idleMinutes}
        onChange={(e) => setS({ ...s, idleMinutes: Math.max(1, Number(e.target.value) || 5) })}
      />
      <label className="f">设备名（同步时标识本机）</label>
      <input type="text" value={s.deviceName} onChange={(e) => setS({ ...s, deviceName: e.target.value })} />
      <div className="row" style={{ marginTop: 8 }}>
        <button onClick={() => void save()}>保存</button>
        {msg && <span className="okmsg fit">{msg}</span>}
      </div>
    </section>
  );
}

/* ---------------- 同步 ---------------- */

function SyncSettings({ onChanged }: { onChanged: () => void }) {
  const [serverUrl, setServerUrl] = useState('');
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    void bg<Settings>({ type: 'GET_SETTINGS' }).then((s) => {
      // 未配置过则预填官方默认服务器，用户只需填邮箱即可连接
      setServerUrl(s.serverUrl || DEFAULT_SERVER_URL);
      setEmail(s.email);
      setConnected(!!s.serverUrl);
    });
  }, []);

  const connect = async () => {
    setMsg('');
    if (!serverUrl.trim() || !email.trim()) {
      setMsg('请填写服务器地址和邮箱');
      return;
    }
    setBusy(true);
    try {
      await bg({ type: 'CONNECT_SYNC', serverUrl: serverUrl.trim(), email: email.trim() });
      setConnected(true);
      setMsg('已连接并完成首次同步');
      onChanged();
    } catch (e) {
      setMsg(`连接失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const disconnect = async () => {
    await bg({ type: 'DISCONNECT_SYNC' });
    await bg({ type: 'SAVE_SETTINGS', settings: { serverUrl: '' } });
    setConnected(false);
    setMsg('已断开同步（本地数据保留）');
    onChanged();
  };

  return (
    <section>
      <h3>同步服务</h3>
      <p className="hint">
        默认使用官方 Cloudflare 同步服务（只存储密文，服务器解不开你的密码）。
        也可改为自建地址。填写邮箱后点「连接并同步」即可多设备同步。
      </p>
      <label className="f">服务器地址</label>
      <input
        type="text"
        value={serverUrl}
        onChange={(e) => setServerUrl(e.target.value)}
        placeholder={DEFAULT_SERVER_URL}
        autoComplete="off"
      />
      <label className="f">邮箱（同步账号标识）</label>
      <input type="text" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" />
      <div className="row" style={{ marginTop: 8 }}>
        {!connected ? (
          <button onClick={() => void connect()} disabled={busy}>
            {busy ? '连接中…' : '连接并同步'}
          </button>
        ) : (
          <button className="danger" onClick={() => void disconnect()}>
            断开同步
          </button>
        )}
      </div>
      {msg && <div className="hint">{msg}</div>}
    </section>
  );
}

/* ---------------- 备份 ---------------- */

function BackupSection() {
  const [msg, setMsg] = useState('');
  const doExport = async () => {
    try {
      const data = await bg<unknown>({ type: 'EXPORT' });
      download(`zpasswd-backup-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(data, null, 2));
      setMsg('已导出加密备份（JSON，内全为密文）');
    } catch (e) {
      setMsg(`导出失败：${e instanceof Error ? e.message : String(e)}`);
    }
  };
  return (
    <section>
      <h3>加密备份</h3>
      <p className="hint">导出文件包含 salt、wrappedDek 与全部条目密文，没有主密码谁也打不开。建议配合恢复码离线保存。</p>
      <button onClick={() => void doExport()}>导出加密备份</button>
      {msg && <div className="hint">{msg}</div>}
    </section>
  );
}

/* ---------------- 导入 ---------------- */

type CsvKind = 'chrome' | 'bitwarden';

function rowToItem(kind: CsvKind, header: string[], row: string[]): VaultItemPlain | null {
  const get = (name: string) => {
    const i = header.indexOf(name);
    return i >= 0 ? (row[i] ?? '').trim() : '';
  };
  if (kind === 'chrome') {
    const password = get('password');
    if (!password) return null;
    return {
      name: get('name') || get('url') || '导入条目',
      username: get('username'),
      password,
      url: get('url'),
      notes: '',
      totpSeed: '',
    };
  }
  // bitwarden
  const password = get('login_password');
  if (!password) return null;
  return {
    name: get('name') || '导入条目',
    username: get('login_username'),
    password,
    url: get('login_uri'),
    notes: get('notes'),
    totpSeed: get('login_totp'),
  };
}

function ImportSection() {
  const [kind, setKind] = useState<CsvKind>('chrome');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    setBusy(true);
    setMsg('');
    try {
      const text = await f.text();
      const rows = parseCsv(text);
      if (rows.length < 2) throw new Error('CSV 为空或格式不对');
      const header = rows[0].map((h) => h.trim().toLowerCase());
      let count = 0;
      for (const row of rows.slice(1)) {
        const item = rowToItem(kind, header, row);
        if (item) {
          await bg({ type: 'ADD_ITEM', item });
          count++;
        }
      }
      setMsg(`导入完成：${count} 条`);
    } catch (e) {
      setMsg(`导入失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <h3>从其他密码管理器导入</h3>
      <div className="row">
        <select value={kind} onChange={(e) => setKind(e.target.value as CsvKind)} style={{ maxWidth: 220 }}>
          <option value="chrome">Chrome 导出的 CSV</option>
          <option value="bitwarden">Bitwarden 导出的 CSV</option>
        </select>
        <label className="fit">
          <input
            type="file"
            accept=".csv"
            style={{ display: 'none' }}
            onChange={(e) => void onFile(e.target.files?.[0])}
          />
          <button type="button" disabled={busy} onClick={(e) => (e.currentTarget.previousElementSibling as HTMLInputElement)?.click()}>
            {busy ? '导入中…' : '选择 CSV 文件'}
          </button>
        </label>
      </div>
      {msg && <div className="hint">{msg}</div>}
    </section>
  );
}

/* ---------------- 恢复码 ---------------- */

function RecoverySection() {
  const [pw, setPw] = useState('');
  const [words, setWords] = useState<string[] | null>(null);
  const [err, setErr] = useState('');

  const show = async () => {
    setErr('');
    try {
      await bg({ type: 'VERIFY_PASSWORD', password: pw });
      const r = await bg<{ mnemonic: string }>({ type: 'GET_RECOVERY_MNEMONIC' });
      setWords(r.mnemonic.split(' '));
      setPw('');
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section>
      <h3>恢复码</h3>
      <p className="hint">
        24 个单词的纸质恢复码。忘记主密码时可用它重建全部密钥。请抄在纸上离线保存，
        不要截图、不要存网盘。
      </p>
      {!words ? (
        <div className="row">
          <input
            type="password"
            placeholder="再次输入主密码以查看"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void show()}
          />
          <button className="fit" onClick={() => void show()}>
            显示恢复码
          </button>
        </div>
      ) : (
        <div>
          <div className="words">
            {words.map((w, i) => (
              <span key={i}>
                <i>{i + 1}</i>
                {w}
              </span>
            ))}
          </div>
          <button className="ghost" onClick={() => setWords(null)}>
            隐藏
          </button>
        </div>
      )}
      {err && <div className="err">{err}</div>}
    </section>
  );
}

/* ---------------- 危险区 ---------------- */

function DangerZone() {
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState('');
  const [rEmail, setREmail] = useState('');
  const [rPw, setRPw] = useState('');
  const [rBusy, setRBusy] = useState(false);
  const [rMsg, setRMsg] = useState('');

  const reset = async () => {
    if (confirm.trim().toUpperCase() !== 'DELETE') {
      setMsg('请输入 DELETE 确认');
      return;
    }
    if (!window.confirm('最后确认：删除本地全部数据？此操作不可撤销！')) return;
    await bg({ type: 'RESET_VAULT' });
    setMsg('已删除。请关闭本页，重新点击扩展图标创建新 vault。');
  };

  const restore = async () => {
    setRMsg('');
    if (!rEmail.trim() || !rPw) {
      setRMsg('请填写同步邮箱和主密码');
      return;
    }
    if (!window.confirm('从服务器恢复会覆盖本地 vault（本地未同步的数据将丢失），继续吗？')) return;
    setRBusy(true);
    try {
      await bg({ type: 'RESTORE_FROM_SYNC', email: rEmail.trim(), password: rPw });
      setRMsg('恢复成功！请关闭本页，重新点击扩展图标。');
      setRPw('');
    } catch (e) {
      setRMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setRBusy(false);
    }
  };

  return (
    <section>
      <h3 style={{ color: '#ff8a80' }}>危险区</h3>
      <p className="hint">删除本地 vault 的全部数据（密文、设置、同步令牌）。服务端数据不受影响。</p>
      <div className="row">
        <input
          type="text"
          placeholder="输入 DELETE 确认"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <button className="danger fit" onClick={() => void reset()}>
          删除本地 vault
        </button>
      </div>
      {msg && <div className="hint">{msg}</div>}

      <h3 style={{ color: '#ff8a80', marginTop: 16 }}>从同步恢复</h3>
      <p className="hint">
        换设备 / 重装后：用同步邮箱 + 主密码从服务器恢复 vault，会覆盖本地数据。
      </p>
      <label className="f">同步邮箱</label>
      <input type="text" value={rEmail} onChange={(e) => setREmail(e.target.value)} autoComplete="off" />
      <label className="f">主密码</label>
      <input type="password" value={rPw} onChange={(e) => setRPw(e.target.value)} />
      <div className="row" style={{ marginTop: 8 }}>
        <button className="danger" onClick={() => void restore()} disabled={rBusy}>
          {rBusy ? '恢复中…' : '从服务器恢复（覆盖本地）'}
        </button>
      </div>
      {rMsg && <div className="hint">{rMsg}</div>}
    </section>
  );
}
