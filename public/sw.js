'use strict';
// Service worker mínimo: só existe para o Android permitir notificações
// e para que tocar numa notificação abra o chat.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    const open = list.find(c => new URL(c.url).pathname === '/');
    return open ? open.focus() : self.clients.openWindow('/');
  }));
});
