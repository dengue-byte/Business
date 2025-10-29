// static/js/global_socket.js
// IMPORTANT : Ce script doit être chargé sur TOUTES les pages (dans base.html)

document.addEventListener('DOMContentLoaded', () => {
    // On vérifie si l'utilisateur est connecté avant d'ouvrir un socket
    const isLoggedIn = document.cookie.includes('access_token_cookie');

    if (isLoggedIn) {
        const socket = io();

        socket.on('connect', () => {
            console.log('Socket global connecté.');
        });

        /**
         * C'est le listener CLÉ pour le statut "délivré".
         * Il écoute les messages envoyés à la room personnelle de l'utilisateur.
         * * CORRECTION : La logique serveur (on_new_message) garantit déjà
         * que cet événement n'est émis que pour les destinataires.
         * Nous n'avons plus besoin de vérifier l'ID de l'expéditeur ici.
         */
        socket.on('new_message', (msg) => {
            // On accuse simplement réception du message
            socket.emit('message_delivered', { message_id: msg.id });
        });

        /**
         * Gère les notifications en temps réel (la cloche)
         */
        socket.on('new_notification', (data) => {
            console.log('Nouvelle notification:', data.message);
            // Ici, tu peux ajouter la logique pour afficher un "toast"
            // ou simplement mettre à jour le compteur
        });

        socket.on('notification_count_update', (data) => {
            console.log('Mise à jour compteur notif:', data.unread_count);
            const badge = document.getElementById('notification-badge-global');
            if (badge) {
                if (data.unread_count > 0) {
                    badge.textContent = data.unread_count;
                    badge.style.display = 'flex';
                } else {
                    badge.style.display = 'none';
                }
            }
        });

        socket.on('disconnect', () => {
            console.log('Socket global déconnecté.');
        });
    }
});