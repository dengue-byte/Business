// static/js/auth_check.js (Version corrigée et nettoyée)

// --- Fonctions globales ---

window.getCsrfToken = function() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        let [name, value] = cookie.split('=').map(c => c.trim());
        if (name === 'csrf_access_token') return value;
    }
    return null;
};

window.logout = async function() {
    try {
        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken()}
        });
        const data = await response.json();
        if (data.success) {
            localStorage.clear();
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Network error on logout:', error);
    }
};

window.displayMessage = function(message, type, containerId = 'message-container') {
    const container = document.getElementById(containerId);
    if (!container) return;
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = message;
    container.innerHTML = '';
    container.appendChild(messageDiv);
    setTimeout(() => {
        messageDiv.style.opacity = '0';
        setTimeout(() => messageDiv.remove(), 500);
    }, 5000);
};

function showToast(message, link = null) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('a');
    toast.className = 'toast';
    toast.textContent = message;

    if (link) {
        toast.href = link;
        toast.classList.add('clickable');
    }

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4500);
}

function updateUnreadCountBadge(total_unread) {
    console.log('Updating message badge with total:', total_unread);

    // Cible le lien texte "Messages" (desktop)
    const messagesLinkDesktop = document.querySelector('.center-desktop-nav a[href="/messages"]');
    if (messagesLinkDesktop) { // CORRECTION : On vérifie si l'élément existe
        messagesLinkDesktop.querySelector('.nav-notification-badge')?.remove();
        if (total_unread > 0) {
            const badge = document.createElement('span');
            badge.className = 'nav-notification-badge';
            badge.textContent = total_unread > 9 ? '9+' : total_unread;
            messagesLinkDesktop.style.position = 'relative';
            messagesLinkDesktop.appendChild(badge);
        }
    }

    // Cible l'icône messages mobile
    const mobileMessagesIcon = document.querySelector('.mobile-nav-item[href="/messages"]');
    if (mobileMessagesIcon) { // CORRECTION : On vérifie si l'élément existe
        mobileMessagesIcon.querySelector('.nav-notification-badge')?.remove();
        if (total_unread > 0) {
            const badge = document.createElement('span');
            badge.className = 'nav-notification-badge';
            badge.textContent = total_unread > 9 ? '9+' : total_unread;
            mobileMessagesIcon.appendChild(badge);
        }
    }
}

function updateNotificationBadge(unread) {
    const bell = document.querySelector('.notification-bell');
    // CORRECTION MAJEURE : Si la cloche de notification n'existe pas sur la page, on ne fait rien.
    if (!bell) {
        return;
    }
    bell.querySelector('.nav-notification-badge')?.remove();
    if (unread > 0) {
        const badge = document.createElement('span');
        badge.className = 'nav-notification-badge';
        badge.textContent = unread > 9 ? '9+' : unread;
        bell.appendChild(badge);
    }
}


function setupGlobalSocketListeners() {
    // NOTE : On s'assure de n'avoir qu'une seule connexion socket
    if (window.socket) return;
    
    window.socket = io();

    window.socket.on('connect', () => {
        console.log("Socket.IO global connected.");
    });

    window.socket.on('unread_count_update', (data) => {
        updateUnreadCountBadge(data.total_unread);
    });

    window.socket.on('new_notification', (data) => {
        if (data.link && data.link.startsWith('/messages') && window.location.pathname === '/messages') {
            return;
        }
        showToast(data.message, data.link);
    });

    window.socket.on('notification_count_update', (data) => {
        console.log("Notification badge update received:", data.unread_count);
        updateNotificationBadge(data.unread_count);
    });
}

function fetchInitialUnreadCounts() {
    // Récupère les messages non lus
    fetch('/api/chat/unread_info')
        .then(res => res.ok ? res.json() : Promise.reject('Failed to fetch unread messages'))
        .then(data => {
            if (data.success) {
                updateUnreadCountBadge(data.total_unread);
            }
        }).catch(e => console.error("Failed to fetch unread info:", e));

    // Récupère les notifications non lues
    fetch('/api/notifications/unread')
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                updateNotificationBadge(data.unread_count);
            }
        }).catch(e => console.error("Failed to fetch unread notifications:", e));
}

async function checkAuthState() {
    try {
        const response = await fetch('/api/auth_status');
        const data = await response.json();
        
        if (data.is_logged_in) {
            localStorage.setItem('user_id', data.user_id);
            // On lance les logiques "connectées" UNIQUEMENT si l'utilisateur est bien connecté
            setupGlobalSocketListeners();
            fetchInitialUnreadCounts();
        } else {
            localStorage.removeItem('user_id');
        }
    } catch (error) {
        localStorage.removeItem('user_id');
        console.error("Auth check failed:", error);
    }
}


// --- Logique principale au chargement de la page ---
document.addEventListener('DOMContentLoaded', () => {
    // Bouton de déconnexion
    const logoutButton = document.getElementById('logout-button');
    if (logoutButton) {
        logoutButton.addEventListener('click', (event) => {
            event.preventDefault();
            window.logout();
        });
    }

    // Clic sur la cloche de notification
    const notificationBell = document.querySelector('.notification-bell');
    if (notificationBell) {
        notificationBell.addEventListener('click', () => {
            const badge = notificationBell.querySelector('.nav-notification-badge');
            if (badge) {
                badge.style.display = 'none';
            }
        });
    }

    // On vérifie le statut de l'authentification UNE SEULE FOIS, proprement.
    checkAuthState();
});