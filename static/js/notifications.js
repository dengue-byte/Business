// DANS static/js/notifications.js
// REMPLACEZ TOUT LE CONTENU DU FICHIER PAR CE QUI SUIT :

document.addEventListener('DOMContentLoaded', () => {
    const lang = document.documentElement.lang;
    const container = document.getElementById('notifications-list-container');
    const actionsButton = document.getElementById('main-actions-button');
    const actionsDropdown = document.getElementById('main-actions-dropdown');

    let allNotifications = [];
    let selectedNotifIds = new Set();
    let isSelectionMode = false;
    let pressTimer;

    // --- GESTION DE LA SÉLECTION ---

    function enterSelectionMode() {
        if (isSelectionMode) return;
        isSelectionMode = true;
        container.classList.add('selection-mode');
        updateActionsMenu();
    }

    function exitSelectionMode() {
        isSelectionMode = false;
        container.classList.remove('selection-mode');
        selectedNotifIds.clear();
        document.querySelectorAll('.notification-item.selected').forEach(item => {
            item.classList.remove('selected');
        });
        updateActionsMenu();
    }

    function toggleSelection(notifId, element) {
        if (selectedNotifIds.has(notifId)) {
            selectedNotifIds.delete(notifId);
            element.classList.remove('selected');
        } else {
            selectedNotifIds.add(notifId);
            element.classList.add('selected');
        }

        if (selectedNotifIds.size === 0) {
            exitSelectionMode();
        } else {
            updateActionsMenu();
        }
    }

    // --- MISE À JOUR DU MENU D'ACTIONS ---

    function updateActionsMenu() {
        actionsDropdown.innerHTML = '';
        if (isSelectionMode && selectedNotifIds.size > 0) {
            // Menu contextuel (quand des items sont sélectionnés)
            const count = selectedNotifIds.size;
            const markAsReadText = count > 1 ? `Mark the ${count} as read` : 'Mark as read';
            const deleteText = count > 1 ? `Delete the ${count}` : 'Delete';

            actionsDropdown.innerHTML += `<button class="dropdown-item" data-action="mark_read_selected">${markAsReadText}</button>`;
            actionsDropdown.innerHTML += `<button class="dropdown-item danger" data-action="delete_selected">${deleteText}</button>`;
            actionsDropdown.innerHTML += `<hr><button class="dropdown-item" data-action="cancel_selection">Cancel selection</button>`;
        } else {
            // Menu par défaut
            if (allNotifications.length > 0) {
                actionsDropdown.innerHTML += `<button class="dropdown-item" data-action="mark_read_all">Mark all as read</button>`;
                actionsDropdown.innerHTML += `<button class="dropdown-item danger" data-action="delete_all">Delete all</button>`;
            } else {
                 actionsDropdown.innerHTML = `<span class="dropdown-item" style="color: grey;">No action</span>`;
            }
        }
    }

    // --- GESTION DES ÉVÉNEMENTS ---

    async function handleAction(action) {
        let confirmationMessage, apiAction, idsToSend = [];
        
        switch (action) {
            case 'mark_read_all':
                apiAction = 'mark_read';
                break;
            case 'delete_all':
                confirmationMessage = _('Do you really want to delete ALL your notifications?');
                apiAction = 'delete';
                break;
            case 'mark_read_selected':
                apiAction = 'mark_read';
                idsToSend = Array.from(selectedNotifIds);
                break;
            case 'delete_selected':
                confirmationMessage = `Do you really want to delete the ${selectedNotifIds.size} selected notifications?`;
                apiAction = 'delete';
                idsToSend = Array.from(selectedNotifIds);
                break;
            case 'cancel_selection':
                exitSelectionMode();
                return;
        }

        if (confirmationMessage && !confirm(confirmationMessage)) {
            return;
        }

        try {
            const response = await fetch('/api/notifications/bulk-actions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: JSON.stringify({ action: apiAction, notif_ids: idsToSend })
            });
            const data = await response.json();
            displayMessage(data.message, response.ok ? 'success' : 'error');
            if (response.ok) {
                exitSelectionMode();
                loadNotifications(); // Recharger la liste
            }
        } catch (error) {
            displayMessage(lang === 'fr' ? 'Erreur réseau.' : 'Network error.', 'error');
        }
    }

    // --- RENDU ET CHARGEMENT ---

    async function loadNotifications() {
        try {
            const response = await fetch('/api/notifications');
            const data = await response.json();
            if (data.success) {
                allNotifications = data.notifications;
                renderNotifications(allNotifications);
                actionsButton.style.display = allNotifications.length > 0 ? 'block' : 'none';
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            displayMessage(lang === 'fr' ? 'Erreur réseau.' : 'Network error.', 'error');
        }
    }

    function renderNotifications(notifs) {
        container.innerHTML = '';
        if (notifs.length === 0) {
            container.innerHTML = `<p>${lang === 'fr' ? 'Aucune notification.' : 'No notification.'}</p>`;
            return;
        }
        notifs.forEach(notif => {
            const item = document.createElement('div');
            item.className = 'notification-item' + (notif.is_read ? ' read' : '');
            item.dataset.notifId = notif.id;

            const actorInitial = notif.actor_username ? notif.actor_username.charAt(0).toUpperCase() : '?';
            const iconClass = notif.type === 'favorite' ? 'fa-bookmark' : 'fa-star';

            item.innerHTML = `
                <div class="selection-overlay"></div>
                <div class="notif-avatar">${actorInitial}</div>
                <div class="notif-content">
                    <p><strong>${notif.actor_username || '[User]'}</strong> ${notif.message}</p>
                    <span class="timestamp">${new Date(notif.timestamp).toLocaleString(lang)}</span>
                    <i class="notif-icon fas ${iconClass}"></i>
                </div>
            `;
            container.appendChild(item);
        });
    }

    // --- ÉCOUTEURS D'ÉVÉNEMENTS PRINCIPAUX ---
    
    // Clic sur le bouton de menu
    actionsButton.addEventListener('click', (e) => {
        e.stopPropagation();
        updateActionsMenu();
        actionsDropdown.classList.toggle('show');
    });

    // Clic sur une action dans le menu
    actionsDropdown.addEventListener('click', (e) => {
        const action = e.target.dataset.action;
        if (action) {
            handleAction(action);
            actionsDropdown.classList.remove('show');
        }
    });
    
    // Clics sur la liste des notifications (sélection ou navigation)
    container.addEventListener('click', async (e) => {
        const item = e.target.closest('.notification-item');
        if (!item) return;
        
        const notifId = parseInt(item.dataset.notifId, 10);
        const notification = allNotifications.find(n => n.id === notifId);

        if (isSelectionMode || e.ctrlKey) {
            e.preventDefault();
            enterSelectionMode();
            toggleSelection(notifId, item);
        } else {
            // Comportement normal : marquer comme lu et naviguer
            if (notification && notification.link) {
                window.location.href = notification.link;
            }
            if (!notification.is_read) {
                await fetch(`/api/notifications/${notifId}/read`, { method: 'POST', headers: { 'X-CSRF-TOKEN': window.getCsrfToken() } });
            }
        }
    });

    // Gestion du clic long pour mobile
    container.addEventListener('pointerdown', (e) => {
        const item = e.target.closest('.notification-item');
        if (item) {
            pressTimer = window.setTimeout(() => {
                enterSelectionMode();
                toggleSelection(parseInt(item.dataset.notifId, 10), item);
            }, 800); // 800ms pour un appui long
        }
    });

    container.addEventListener('pointerup', () => {
        clearTimeout(pressTimer);
    });

    // Fermer le menu si on clique n'importe où ailleurs
    document.addEventListener('click', () => {
        if (actionsDropdown.classList.contains('show')) {
            actionsDropdown.classList.remove('show');
        }
    });

    // Chargement initial
    loadNotifications();
});