// static/js/push-notifications.js

// Fonction pour convertir la clé publique VAPID
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

async function subscribeUser() {
  if ('serviceWorker' in navigator && 'PushManager' in window) {
    try {
      const registration = await navigator.serviceWorker.ready;

      // Vérifie permission (essentiel pour mobile)
      let permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        console.log(_('Permission denied.'));
        return;
      }

      let subscription = await registration.pushManager.getSubscription();

      if (subscription === null) {
        subscription = await registration.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
        });
      }

      await fetch('/api/save-subscription', {
        method: 'POST',
        body: JSON.stringify(subscription),
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-TOKEN': window.getCsrfToken()
        }
      });
      console.log(_('Push subscription saved.'));

    } catch (error) {
      console.error(_('Push subscription failed: '), error);
    }
  }
}

// Appelle subscribeUser() au load ou sur bouton si besoin
// Lance le processus d'abonnement
subscribeUser();