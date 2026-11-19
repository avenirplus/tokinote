// トキノートの service worker
// - 通知（しつもん）を受け取って表示する。通知の中身はサーバーから取り直す（暗号化した中身を運ばない方式）
// - 画面・ライブラリを保存し、電波が弱くても開けるようにする（画面はネット優先、ライブラリは保存優先）
const CACHE = 'tokinote-v1';
const ASSETS = ['/', '/index.html', '/vendor/pdf.min.mjs', '/vendor/pdf.worker.min.mjs', '/cmaps.json', '/manifest.webmanifest', '/icon-192.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil((async () => { for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k); await self.clients.claim(); })()); });
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/')) return;
  const cacheFirst = u.pathname.startsWith('/vendor/') || u.pathname === '/cmaps.json';
  e.respondWith((async () => {
    const c = await caches.open(CACHE);
    if (cacheFirst) { const hit = await c.match(e.request); if (hit) return hit; }
    try { const r = await fetch(e.request); if (r.ok) c.put(e.request, r.clone()); return r; }
    catch { const hit = await c.match(e.request) || (e.request.mode === 'navigate' ? await c.match('/') : null); if (hit) return hit; throw new Error('offline'); }
  })());
});
self.addEventListener('push', e => {
  e.waitUntil((async () => {
    let title = '🙋 トキノート', body = 'しつもんがとどきました', url = '/';
    try {
      const r = await fetch('/api/q/latest', { credentials: 'include', cache: 'no-store' });
      if (r.ok) {
        const q = await r.json();
        if (q.test) { title = '🔔 トキノート'; body = '通知のテストです。とどいています！'; }
        else { title = `🙋 ${q.who || '子ども'} からしつもん`; body = `${q.book || ''} ${q.p != null ? (q.p + 1) + 'ページ' : ''}${q.text ? '「' + q.text + '」' : q.aud ? '（声のしつもん）' : ''}`.trim(); url = `/?watch=${encodeURIComponent(q.L || '')}&q=${encodeURIComponent(q.id || '')}`; }
      }
    } catch {}
    await self.registration.showNotification(title, { body, tag: 'tokinote-q', renotify: true, data: { url }, icon: '/icon-192.png', badge: '/icon-192.png' });
  })());
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = e.notification.data?.url || '/';
  e.waitUntil((async () => {
    const cs = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of cs) { try { await c.focus(); c.postMessage({ t: 'openQ', url }); return; } catch {} }
    await self.clients.openWindow(url);
  })());
});
