const CACHE_NAME = 'job-board-v3';  // увеличили версию, чтобы старый кэш сломался
const urlsToCache = [
  '/',
  '/index.html',
  '/admin.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting(); // сразу активируем новый SW
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.map(key => {
        if (key !== CACHE_NAME) return caches.delete(key);
      })
    ))
  );
  self.clients.claim(); // перехватываем все запросы сразу
});

self.addEventListener('fetch', event => {
  // Для запросов к HTML и корню сначала пробуем сеть, потом кэш
  if (event.request.mode === 'navigate' || event.request.url === self.location.origin + '/') {
    event.respondWith(
      fetch(event.request).catch(() => caches.match(event.request))
    );
    return;
  }
  // Для остальных ресурсов: сначала кэш, потом сеть
  event.respondWith(
    caches.match(event.request).then(response => {
      return response || fetch(event.request);
    })
  );
});