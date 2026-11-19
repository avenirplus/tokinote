// トキノート Cloudflare Worker
// - 画面（public/）は Workers Static Assets がそのまま配信
// - /api/* はすべて Durable Object「Family」1つに渡す（家族のデータ・PDF・リアルタイム中継・パスコード認証）
// 必要な設定：Worker のシークレット APP_PIN（4けた）だけ。セッション用の鍵は DO が自動で作って保存する。

import { DurableObject } from 'cloudflare:workers';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      const stub = env.FAMILY.get(env.FAMILY.idFromName('family'));
      return stub.fetch(request);
    }
    return env.ASSETS.fetch(request);
  },
};

const COOKIE = 'tk_s';
const SESSION_DAYS = 180;
const CHUNK = 1024 * 1024;          // PDFは1MBずつに分けて保存（1行の上限2MBより小さく）
const MAX_PDF = 95 * 1024 * 1024;   // リクエスト本体の上限（無料プラン100MB）より少し小さく

const json = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });

const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export class Family extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, val TEXT NOT NULL, updated INTEGER NOT NULL)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS blob (id TEXT NOT NULL, idx INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (id, idx))`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS bloblen (id TEXT PRIMARY KEY, size INTEGER NOT NULL, name TEXT, updated INTEGER NOT NULL)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`);
  }

  /* ---------- 小さな道具 ---------- */
  meta(k) { const r = this.sql.exec(`SELECT v FROM meta WHERE k=?`, k).toArray(); return r.length ? r[0].v : null; }
  setMeta(k, v) { this.sql.exec(`INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v); }

  async hmacKey() {
    let raw = this.meta('sessionKey');
    if (!raw) { const k = crypto.getRandomValues(new Uint8Array(32)); raw = b64url(k); this.setMeta('sessionKey', raw); }
    const bytes = Uint8Array.from(atob(raw.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((raw.length + 3) % 4)), c => c.charCodeAt(0));
    return crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  }
  async sign(payload) { const key = await this.hmacKey(); return b64url(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload))); }
  async makeToken() { const exp = Date.now() + SESSION_DAYS * 86400000; const gen = this.meta('sessionGen') || '1'; const p = `${exp}.${gen}`; return `${p}.${await this.sign(p)}`; }
  async authed(request) {
    const c = request.headers.get('cookie') || '';
    const m = c.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`)); if (!m) return false;
    const [exp, gen, sig] = m[1].split('.'); if (!exp || !gen || !sig) return false;
    if (+exp < Date.now() || gen !== (this.meta('sessionGen') || '1')) return false;
    return timingSafeEqual(sig, await this.sign(`${exp}.${gen}`));
  }

  /* ---------- パスコード：連続でまちがえたら待たせる ---------- */
  lockState(ip) {
    const raw = this.meta('fail:' + ip); return raw ? JSON.parse(raw) : { n: 0, until: 0 };
  }
  async login(request) {
    const pin = this.env.APP_PIN;
    if (!pin || !/^\d{4,8}$/.test(pin)) return json({ ok: false, error: 'not_configured' }, 503);
    const ip = request.headers.get('cf-connecting-ip') || 'local';
    const day = new Date().toISOString().slice(0, 10);
    const g = JSON.parse(this.meta('failDay') || '{}');
    const now = Date.now();
    const st = this.lockState(ip);
    if (st.until > now) return json({ ok: false, error: 'locked', wait: Math.ceil((st.until - now) / 1000) }, 429);
    if (g.day === day && g.n >= 100) return json({ ok: false, error: 'locked_today' }, 429);
    let body = {}; try { body = await request.json(); } catch {}
    if (timingSafeEqual(String(body.pin || ''), pin)) {
      this.sql.exec(`DELETE FROM meta WHERE k=?`, 'fail:' + ip);
      const tok = await this.makeToken();
      return json({ ok: true }, 200, { 'set-cookie': `${COOKIE}=${tok}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly; Secure; SameSite=Strict` });
    }
    st.n += 1;
    if (st.n >= 5) st.until = now + Math.min(24 * 3600, 60 * 2 ** (st.n - 5)) * 1000;   // 5回目から1分、2分、4分…（最大1日）
    this.setMeta('fail:' + ip, JSON.stringify(st));
    this.setMeta('failDay', JSON.stringify({ day, n: g.day === day ? g.n + 1 : 1 }));
    return json({ ok: false, error: 'wrong', left: Math.max(0, 5 - st.n), wait: st.until > now ? Math.ceil((st.until - now) / 1000) : 0 }, 401);
  }

  /* ---------- 入口 ---------- */
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === '/api/health') return json({ app: 'tokinote', v: 1, authed: await this.authed(request), configured: !!this.env.APP_PIN });
    if (path === '/api/login' && request.method === 'POST') return this.login(request);
    if (path === '/api/logout' && request.method === 'POST') return json({ ok: true }, 200, { 'set-cookie': `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict` });
    if (!(await this.authed(request))) return json({ ok: false, error: 'auth' }, 401);

    // すべての端末をログアウトさせる（パスコードを変えたとき用）
    if (path === '/api/logout-all' && request.method === 'POST') { this.setMeta('sessionGen', String(Date.now())); return json({ ok: true }); }

    if (path === '/api/kv') {
      const key = url.searchParams.get('key') || '';
      if (request.method === 'GET') {
        const r = this.sql.exec(`SELECT val FROM kv WHERE key=?`, key).toArray();
        return r.length ? new Response(r[0].val, { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } }) : json({ ok: false }, 404);
      }
      if (request.method === 'PUT') {
        const text = await request.text();
        if (text.length > 1_900_000) return json({ ok: false, error: 'too_large' }, 413);
        let v; try { v = JSON.parse(text); } catch { return json({ ok: false, error: 'bad_json' }, 400); }
        if (!key || key.length > 300) return json({ ok: false, error: 'bad_key' }, 400);
        this.sql.exec(`INSERT INTO kv(key,val,updated) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET val=excluded.val, updated=excluded.updated`, key, text, +(v.updated || Date.now()));
        return json({ ok: true });
      }
    }
    // コレクション（key の「/」区切りで、その直下だけ）を返す。where は field=value の1条件
    if (path === '/api/kv/list' && request.method === 'GET') {
      const col = url.searchParams.get('col') || '';
      const field = url.searchParams.get('field'), value = url.searchParams.get('value');
      const prefix = col ? col + '/' : '';
      const rows = prefix
        ? this.sql.exec(`SELECT key,val FROM kv WHERE substr(key,1,?)=?`, prefix.length, prefix).toArray()
        : this.sql.exec(`SELECT key,val FROM kv WHERE instr(key,'/')=0`).toArray();
      const out = [];
      for (const r of rows) {
        const rest = r.key.slice(prefix.length); if (rest.includes('/')) continue;
        const data = JSON.parse(r.val);
        if (field && String(data[field]) !== value) continue;
        out.push({ id: rest, data });
      }
      return json(out);
    }
    // PDF本体
    const pm = path.match(/^\/api\/(?:pdf|blob)\/([a-f0-9]{8,64})$/);   // PDF と、アドバイスの画像
    if (pm) {
      const id = pm[1];
      if (request.method === 'HEAD' || request.method === 'GET') {
        const m = this.sql.exec(`SELECT size,name FROM bloblen WHERE id=?`, id).toArray();
        if (!m.length) return new Response(null, { status: 404 });
        if (request.method === 'HEAD') return new Response(null, { headers: { 'content-length': String(m[0].size) } });
        const out = new Uint8Array(m[0].size); let off = 0;
        for (const r of this.sql.exec(`SELECT data FROM blob WHERE id=? ORDER BY idx`, id)) { const d = new Uint8Array(r.data); out.set(d, off); off += d.length; }
        return new Response(out, { headers: { 'content-type': path.startsWith('/api/blob/') ? 'image/jpeg' : 'application/pdf', 'cache-control': 'private, max-age=0' } });
      }
      if (request.method === 'PUT') {
        const len = +(request.headers.get('content-length') || 0);
        if (len > MAX_PDF) return json({ ok: false, error: 'too_large' }, 413);
        const buf = new Uint8Array(await request.arrayBuffer());
        if (buf.length > MAX_PDF) return json({ ok: false, error: 'too_large' }, 413);
        const name = (url.searchParams.get('name') || '').slice(0, 200);
        this.ctx.storage.transactionSync(() => {
          this.sql.exec(`DELETE FROM blob WHERE id=?`, id);
          for (let i = 0, k = 0; i < buf.length; i += CHUNK, k++) this.sql.exec(`INSERT INTO blob(id,idx,data) VALUES(?,?,?)`, id, k, buf.subarray(i, i + CHUNK));
          this.sql.exec(`INSERT INTO bloblen(id,size,name,updated) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET size=excluded.size, name=excluded.name, updated=excluded.updated`, id, buf.length, name, Date.now());
        });
        return json({ ok: true, size: buf.length });
      }
    }
    if (path === '/api/pdfs' && request.method === 'GET') {
      return json(this.sql.exec(`SELECT id,size,name,updated FROM bloblen`).toArray());
    }
    // リアルタイム中継（見守り）
    if (path === '/api/live') {
      if (request.headers.get('upgrade') !== 'websocket') return json({ ok: false }, 426);
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1]);
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    return json({ ok: false, error: 'not_found' }, 404);
  }

  /* ---------- WebSocket（ハイバネーション対応：待っている間は課金されない） ---------- */
  async webSocketMessage(ws, msg) {
    if (typeof msg !== 'string' || msg.length > 1_000_000) return;
    let m; try { m = JSON.parse(msg); } catch { return; }
    if (m.t === 'hello') {
      // 見守る側が来たら、各子どもが今どこを開いているかを返す
      const rows = this.sql.exec(`SELECT k,v FROM meta WHERE substr(k,1,4)='cur:'`).toArray();
      ws.send(JSON.stringify({ t: 'curAll', cur: rows.map(r => JSON.parse(r.v)) }));
      return;
    }
    if (m.t === 'ping') { ws.send('{"t":"pong"}'); return; }
    if (m.t === 'cur' && m.L) this.setMeta('cur:' + m.L, JSON.stringify({ L: m.L, b: m.b, p: m.p, name: m.name || '', at: Date.now() }));
    for (const other of this.ctx.getWebSockets()) {
      if (other === ws) continue;
      try { other.send(msg); } catch {}
    }
  }
  async webSocketClose(ws, code) { try { ws.close(code, 'bye'); } catch {} }
  async webSocketError() {}
}
