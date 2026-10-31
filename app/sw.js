// Service worker: deixa o app instalável e sempre busca a versão mais nova na internet.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const u = new URL(e.request.url);
  if (u.origin !== location.origin) return;
  e.respondWith(fetch(e.request, { cache: 'no-cache' }));
});

// Avisos no celular: o servidor manda {titulo, texto}; aqui viram uma notificação do aparelho.
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { texto: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.titulo || 'Corrida OP', {
    body: d.texto || '', icon: 'icon-192.png', badge: 'icon-192.png', tag: d.tag || 'corrida-op', renotify: true, data: { url: './' }
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
    const aberta = cs.find(c => c.url.startsWith(self.registration.scope));
    if (aberta) return aberta.focus();
    return self.clients.openWindow(self.registration.scope);
  }));
});
