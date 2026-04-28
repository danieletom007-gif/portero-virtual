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
      vibrate:  [300, 100, 300, 100, 300],
      actions: [
        { action: 'contestar', title: '📞 Contestar' },
        { action: 'rechazar',  title: '❌ Rechazar'  }
      ],
      data: { url: data.url || '/portero-virtual/vecino.html' }
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const data   = e.notification.data || {};
  const url    = data.url || '/portero-virtual/vecino.html';
  const action = e.action;

  // Si rechaza — cerrar la notificación sin abrir la app
  if (action === 'rechazar') return;

  // Si contesta o pulsa la notificación — abrir la app con la URL completa
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      const vecino = list.find(c => c.url.includes('vecino'));
      if (vecino) {
        return vecino.focus().then(c => {
          if (c && 'navigate' in c) return c.navigate(url);
        }).catch(() => clients.openWindow(url));
      }
      return clients.openWindow(url);
    })
  );
});
