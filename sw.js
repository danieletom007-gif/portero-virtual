const CACHE_NAME = 'portero-v3';

self.addEventListener('install', e => {
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('push', e => {
  if (!e.data) return;
  let data;
  try { data = e.data.json(); } catch { data = { title: '🔔 Llamada', body: e.data.text() }; }

  e.waitUntil(
    self.registration.showNotification(data.title || '🔔 Alguien llama al portal', {
      body:    data.body  || 'Hay una visita esperando.',
      icon:    '/portero-virtual/icon-192.png',
      badge:   '/portero-virtual/icon-192.png',
      tag:     'portero-llamada',
      renotify: true,
      requireInteraction: true,
      data:    { url: data.url || '/portero-virtual/vecino.html' }
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const data = e.notification.data || {};
  const url  = data.url || '/portero-virtual/vecino.html';

  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      // Si ya hay una ventana de vecino abierta, navegar a la URL con contestar=true
      for (const c of list) {
        if (c.url.includes('vecino')) {
          return c.navigate(url).then(client => client ? client.focus() : clients.openWindow(url));
        }
      }
      // Si no hay ventana abierta, abrir una nueva
      return clients.openWindow(url);
    })
  );
});
