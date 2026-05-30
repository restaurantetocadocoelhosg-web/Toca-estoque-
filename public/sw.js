const CACHE = 'toca-estoque-v2';
const STATIC = ['/'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // API e o proprio sw.js sempre vao para a rede — nunca cacheia dados dinamicos
  if (url.pathname.startsWith('/api/') || url.pathname === '/sw.js') {
    e.respondWith(fetch(e.request));
    return;
  }

  // Para o resto: rede primeiro, cache como fallback (garante versao nova quando online)
  e.respondWith(
    fetch(e.request)
      .then(res => {
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
