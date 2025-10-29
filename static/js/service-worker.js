// Version 6: Incrémentez ce numéro pour forcer la mise à jour du cache
const CACHE_NAME = 'business-pwa-cache-v34'; 
const urlsToCache = [
  '/',
  '/login',
  '/posts',
  '/static/css/style.css',
  '/static/js/auth_check.js',
  '/static/images/favicon-192x192.png',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css'
];

// 1. Installation: Mise en cache des ressources essentielles
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Cache ouvert');
        return cache.addAll(urlsToCache);
      })
  );
  self.skipWaiting(); // Force le nouveau Service Worker à s'activer immédiatement
});

// 2. Activation: Nettoyage des anciens caches
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            console.log('Suppression de l\'ancien cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  return self.clients.claim(); // Prend le contrôle de toutes les pages ouvertes
});

// 3. Fetch: Interception des requêtes réseau (AVEC LA CORRECTION FINALE)
self.addEventListener('fetch', event => {
    const { request } = event;

    // Pour les requêtes API ou non-GET, on va toujours sur le réseau, sans mise en cache.
    if (request.url.includes('/api/') || request.method !== 'GET') {
        event.respondWith(fetch(request));
        return;
    }

    // Stratégie "Réseau d'abord, puis cache" pour les fichiers CSS et JS
    if (request.url.endsWith('.css') || request.url.endsWith('.js')) {
        event.respondWith(
            fetch(request)
                .then(networkResponse => {
                    const responseClone = networkResponse.clone();
                    // *** CORRECTION : On ne met en cache que les réponses complètes (status 200) ***
                    if (networkResponse.status === 200) {
                        caches.open(CACHE_NAME).then(cache => {
                            cache.put(request, responseClone);
                        });
                    }
                    return networkResponse;
                })
                .catch(() => {
                    // Si le réseau échoue, on cherche dans le cache
                    return caches.match(request);
                })
        );
        return;
    }

    // Stratégie "Cache d'abord, puis réseau" pour tout le reste (pages, polices, images...)
    event.respondWith(
        caches.match(request).then(cachedResponse => {
            if (cachedResponse) {
                return cachedResponse; // Servir depuis le cache
            }
            // Sinon, aller chercher sur le réseau et mettre en cache
            return fetch(request).then(networkResponse => {
                const responseClone = networkResponse.clone();
                // *** CORRECTION : On applique la même vérification ici ***
                if (networkResponse.status === 200) {
                    caches.open(CACHE_NAME).then(cache => {
                        cache.put(request, responseClone);
                    });
                }
                return networkResponse;
            });
        })
    );
});


// 4. Push: Réception d'une notification push
self.addEventListener('push', event => {
    const data = event.data.json();
    const title = data.title || "Nouvelle Notification";
    const options = {
        body: data.body,
        icon: data.icon || '/static/images/favicon-192x192.png',
        badge: data.badge || '/static/images/logo-badge-b.png',
        data: {
            url: data.data.url 
        }
    };
    event.waitUntil(self.registration.showNotification(title, options));
});

// 5. Notification Click: Gestion du clic sur une notification
self.addEventListener('notificationclick', event => {
    event.notification.close();
    const urlToOpen = new URL(event.notification.data.url, self.location.origin).href;

    const promiseChain = clients.matchAll({
        type: 'window',
        includeUncontrolled: true
    }).then(clientList => {
        for (const client of clientList) {
            if (client.url === urlToOpen && 'focus' in client) {
                return client.focus();
            }
        }
        if (clients.openWindow) {
            return clients.openWindow(urlToOpen);
        }
    });

    event.waitUntil(promiseChain);
});