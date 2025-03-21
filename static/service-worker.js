const CACHE_NAME = "palmcoast-cache-v1";
const urlsToCache = ["/", "/scan", "/static/style.css", "/static/beep.mp3"];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener("fetch", event => {
  event.respondWith(
    caches.match(event.request).then(response => response || fetch(event.request))
  );
});
