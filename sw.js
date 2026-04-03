const CACHE_NAME = 'job-board-v4';
const urlsToCache = [
  '/',
  '/index.html',
  '/admin.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png'
];

// При установке кэшируем только статику
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
  self.skipWaiting(); // активируем сразу
});

// При активации удаляем старый кэш
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.map(key => {
        if (key !== CACHE_NAME) return caches.delete(key);
      })
    ))
  );
  self.clients.claim(); // захватываем все клиенты
});

// Перехват запросов
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  // Для HTML и корневого запроса всегда сначала сеть, потом кэш (fallback)
  if (event.request.mode === 'navigate' || url.pathname === '/') {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          // Клонируем и кэшируем новую версию
          const responseClone = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, responseClone);
          });
          return response;
        })
        .catch(() => caches.match(event.request))
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