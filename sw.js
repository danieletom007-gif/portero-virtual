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
      // Vibración larga tipo llamada entrante
      vibrate:  [500, 200, 500, 200, 500, 200, 500, 200, 500, 200, 500],
     data: { url: data.url || '/portero-virtual/vecino.html' }
    }).then(() => {
      if (data.type && data.type !== 'call') {
        return self.clients.matchAll({ type: 'window', includeUncontrolled: true })
          .then(clients => {
            clients.forEach(client => {
              client.postMessage({ type: 'notice', title: data.title, body: data.body });
            });
          });
      }
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const data = e.notification.data || {};
  const url  = data.url || '/portero-virtual/vecino.html';

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
