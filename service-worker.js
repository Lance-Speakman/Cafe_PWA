// A name for this version of the cache
const CACHE_NAME = "cafe-finigan-v1";

const STATIC_ASSETS = [
    "/templates/main.html",
    "/templates/menu.html",
    "/templates/orders.html",
    "/templates/thanks.html",
    "/static/styles.css",
    "/static/menu.js",
    "/static/orders.js",
    "/static/thanks.js",
    "/static/images/icons/logo-192.png",
    "/static/images/icons/logo-512.png",
    "/static/images/logo.png",
    "/static/images/hero.jpg",
    "/static/images/menu-banner.jpg",
    "/static/images/eggs.jpg"
];

// Install event: pre-cache all static assets
self.addEventListener("install", event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => {
            return cache.addAll(STATIC_ASSETS);
        })
    );
});

// Activate event: remove old caches that don't match the current version
self.addEventListener("activate", event => {
    event.waitUntil(
        caches.keys().then(keys => {
            return Promise.all(
                keys.map(key => {
                    if (key !== CACHE_NAME) {
                        return caches.delete(key);
                    }
                })
            );
        })
    );
});

// Fetch event: use cache first, then network
self.addEventListener("fetch", event => {
    const requestUrl = event.request.url;

    // Never cache backend API calls to Flask
    if (requestUrl.startsWith("http://127.0.0.1:5050")) {
        return;
    }

    event.respondWith(
        caches.match(event.request).then(cachedResponse => {
            // If we have a cached response, return it; otherwise go to the network
            return cachedResponse || fetch(event.request);
        })
    );
});
