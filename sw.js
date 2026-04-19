// sw.js — Service Worker del Portero Virtual SaaS

const CACHE_NAME = 'portero-saas-v1';

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache =>
      cache.addAll(['/vecino.html', '/visitante.html'])
    )
  );
  self.skipWaiting();
});

self.addEventListener('activate', () => self.clients.claim());

// ── Notificación push recibida (navegador cerrado) ────────────────────────
self.addEventListener('push', event => {
  let data = {};
  try { data = event.data.json(); } catch { data = { title: 'Llamada en el portal' }; }

  const options = {
    body: data.body || 'Hay una visita en el portal. Pulsa para contestar.',
    icon: '/icon-192.png',
    badge: '/icon-96.png',
    vibrate: [200, 100, 200, 100, 200, 100, 200],
    requireInteraction: true,
    tag: 'portero-call',
    renotify: true,
    data: {
      url: data.url || '/vecino.html?contestar=true',
      room: data.room || ''
    },
    actions: [
      { action: 'accept', title: '📞 Contestar' },
      { action: 'reject', title: '✕ Rechazar' }
    ]
  };

  event.waitUntil(
    self.registration.showNotification(data.title || '🔔 Llamada en el portal', options)
  );
});

// ── El vecino pulsa la notificación ──────────────────────────────────────
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const action = event.action;
  const data   = event.notification.data || {};
  const url    = action === 'reject' ? '/vecino.html' : (data.url || '/vecino.html?contestar=true');

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const client of list) {
        if (client.url.includes('vecino') && 'focus' in client) {
          client.focus();
          client.navigate(url);
          return;
        }
      }
      return clients.openWindow(url);
    })
  );

  if (action === 'reject' && data.room) {
    clients.matchAll({ type: 'window' }).then(list => {
      list.forEach(c => c.postMessage({ type: 'reject-from-notification', room: data.room }));
    });
  }
});
