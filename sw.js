const CACHE_NAME = 'portero-v4';

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
  try { 
    data = e.data.json(); 
  } catch { 
    data = { title: '🔔 Llamada', body: e.data.text() }; 
  }

  e.waitUntil(
    self.registration.showNotification(data.title || '🔔 Alguien llama al portal', {
      body:     data.body || 'Hay una visita esperando.',
      icon:     '/portero-virtual/icon-192.png',
      badge:    '/portero-virtual/icon-192.png',
      tag:      'portero-llamada',
      renotify: true,
      requireInteraction: true,

      // 🔥 CAMBIO IMPORTANTE: añadir ?contestar=true
      data:     { url: data.url || '/portero-virtual/vecino.html?contestar=true' }
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const data = e.notification.data || {};

  // 🔥 CAMBIO IMPORTANTE: añadir ?contestar=true
  const url  = data.url || '/portero-virtual/vecino.html?contestar=true';

  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      // Buscar ventana de vecino ya abierta
      const vecino = list.find(c => c.url.includes('vecino'));

      if (vecino) {
        // Hay ventana abierta — traerla al frente y navegar a la URL
        return vecino.focus().then(c => {
          if (c && 'navigate' in c) {
            return c.navigate(url);
          }
        }).catch(() => {
          // Si navigate falla, abrir nueva ventana
          return clients.openWindow(url);
        });
      }

      // No hay ventana abierta — abrir la URL directamente
      return clients.openWindow(url);
    })
  );
});
