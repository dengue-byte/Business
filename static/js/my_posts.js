// static/js/my_posts.js (Version finale corrigée - Réintégration des boutons d'action stylisés)

document.addEventListener('DOMContentLoaded', () => {
    // --- Initialisation ---
    const container = document.getElementById('my-posts-list-container');
    const mainActionsButton = document.getElementById('main-actions-button');
    const mainActionsDropdown = document.getElementById('main-actions-dropdown');
    let allPosts = [];
    let selectedPostIds = new Set();
    let isSelectionMode = false;

    // --- FONCTIONS DE GESTION DE L'INTERFACE ---

    function enterSelectionMode() {
        if (isSelectionMode) return;
        isSelectionMode = true;
        container.classList.add('selection-mode');
        updateMainActionsMenu();
    }

    function exitSelectionMode() {
        isSelectionMode = false;
        container.classList.remove('selection-mode');
        selectedPostIds.clear();
        document.querySelectorAll('.post-card.selected').forEach(card => card.classList.remove('selected'));
        updateMainActionsMenu();
    }

    // --- GESTION DES MENUS CONTEXTUELS ---

    function updateMainActionsMenu() {
        if (!mainActionsDropdown) return;
        mainActionsDropdown.innerHTML = '';
        if (selectedPostIds.size > 0) {
            // --- MENU EN MODE SÉLECTION ---
            const selectedPosts = allPosts.filter(p => selectedPostIds.has(p.id));
            if (selectedPostIds.size === 1) {
                const post = selectedPosts[0];
                mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="${post.is_visible ? 'hide' : 'show'}-selected">${post.is_visible ? _('Hide') : _('Show')}</button>`;
                mainActionsDropdown.innerHTML += `<a href="/edit_post/${post.id}" class="dropdown-item" data-action="edit-selected">${_('Edit')}</a>`;
            } else {
                const allVisible = selectedPosts.every(p => p.is_visible);
                const allHidden = selectedPosts.every(p => !p.is_visible);
                if (allVisible) mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="hide-selected">${_('Hide selection')}</button>`;
                else if (allHidden) mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="show-selected">${_('Show selection')}</button>`;
            }
            mainActionsDropdown.innerHTML += `<button class="dropdown-item danger" data-action="delete-selected">${_('Delete selection')}</button>`;
            mainActionsDropdown.innerHTML += `<hr><button class="dropdown-item" data-action="cancel-selection">${_('Cancel selection')}</button>`;
        } else {
            // --- MENU PAR DÉFAUT ---
            if (allPosts.some(p => p.is_visible)) mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="hide-all">${_('Hide all')}</button>`;
            if (allPosts.some(p => !p.is_visible)) mainActionsDropdown.innerHTML += `<button class="dropdown-item" data-action="show-all">${_('Show all')}</button>`;
            if (allPosts.length > 0) mainActionsDropdown.innerHTML += `<button class="dropdown-item danger" data-action="delete-all">${_('Delete all')}</button>`;
        }
    }

    // --- GESTION DES ACTIONS (CLICS) ---
    
     async function handleDeletePost(postId) {
        if (confirm(_('Are you sure you want to delete this ad?'))) {
            try {
                const response = await fetch(`/api/posts/${postId}`, {
                    method: 'DELETE',
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() } // Utilise la fonction globale
                });
                const data = await response.json();
                if (data.success) {
                    displayMessage(_('Ad deleted successfully!'), 'success');
                    allPosts = allPosts.filter(p => p.id !== postId);
                    renderMyPosts(allPosts);
                    updateMainActionsMenu();
                } else {
                    displayMessage(data.message || _('Failed to delete ad.'), 'error');
                }
            } catch (error) {
                console.error('Delete error:', error);
                displayMessage(_('An error occurred while deleting the ad.'), 'error');
            }
        }
    }

     async function handleToggleVisibility(postId) {
        const post = allPosts.find(p => p.id === postId);
        if (!post) return;
        
        const action = post.is_visible ? 'hide' : 'show';
        const confirmationMessage = post.is_visible 
            ? _('Are you sure you want to hide this ad?') 
            : _('Are you sure you want to show this ad?');

        if (confirm(confirmationMessage)) {
            try {
                // L'URL inclut maintenant "toggle_"
                const response = await fetch(`/api/posts/${postId}/toggle_visibility`, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': window.getCsrfToken() // Utilise la fonction globale
                    },
                    body: JSON.stringify({ action: action })
                });
                const data = await response.json();
                if (data.success) {
                    post.is_visible = !post.is_visible;
                    displayMessage(data.message, 'success');
                    renderMyPosts(allPosts);
                    updateMainActionsMenu();
                } else {
                    displayMessage(data.message || _('Failed to update visibility.'), 'error');
                }
            } catch (error) {
                console.error('Visibility toggle error:', error);
                displayMessage(_('An error occurred while updating the visibility.'), 'error');
            }
        }
    }

    async function performBulkAction(endpoint, body) {
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: JSON.stringify(body)
            });
            const data = await response.json();
            if (data.success) {
                displayMessage(data.message, 'success');
                await loadMyPosts();
                exitSelectionMode();
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            console.error('Bulk action error:', error);
            displayMessage(_('Failed to perform action.'), 'error');
        }
    }
    
    if (mainActionsDropdown) {
        mainActionsDropdown.addEventListener('click', async (e) => {
            const action = e.target.dataset.action;
            if (!action) return;

            let postIds;
            let confirmationMessage;
            let endpoint;
            let body;

            if (action.includes('all')) {
                postIds = allPosts.map(p => p.id);
            } else if (action.includes('selected')) {
                postIds = Array.from(selectedPostIds);
            }

            switch (action) {
                case 'hide-all':
                case 'hide-selected':
                    confirmationMessage = _("Hide all selected ads?");
                    endpoint = '/api/posts/bulk-visibility';
                    body = { post_ids: postIds, action: 'hide' };
                    break;
                case 'show-all':
                case 'show-selected':
                    confirmationMessage = _("Show all selected ads?");
                    endpoint = '/api/posts/bulk-visibility';
                    body = { post_ids: postIds, action: 'show' };
                    break;
                case 'delete-all':
                case 'delete-selected':
                    confirmationMessage = _("Permanently delete the selected ads?");
                    endpoint = '/api/posts/bulk-delete';
                    body = { post_ids: postIds };
                    break;
                case 'cancel-selection':
                    exitSelectionMode();
                    return;
                default:
                    return;
            }

            if (postIds && postIds.length > 0 && confirm(confirmationMessage)) {
                await performBulkAction(endpoint, body);
            }
        });
    }

    if (container) {
        container.addEventListener('click', (e) => {
            const card = e.target.closest('.post-card');
            if (!card) return;

            const postId = parseInt(card.dataset.postId, 10);
            
            // Si le clic vient d'un bouton d'action, on le gère et on arrête tout
            const deleteBtn = e.target.closest('.delete-button');
            const toggleBtn = e.target.closest('.toggle-visibility-button');
            
            if (deleteBtn) {
                e.preventDefault();
                handleDeletePost(postId);
                return;
            }
            if (toggleBtn) {
                e.preventDefault();
                handleToggleVisibility(postId);
                return;
            }

            // Si on est en mode sélection, on gère la sélection/désélection
            if (isSelectionMode) {
                e.preventDefault();
                if (selectedPostIds.has(postId)) {
                    selectedPostIds.delete(postId);
                    card.classList.remove('selected');
                } else {
                    selectedPostIds.add(postId);
                    card.classList.add('selected');
                }
                if (selectedPostIds.size === 0) {
                    exitSelectionMode();
                } else {
                    updateMainActionsMenu();
                }
            }
            // Si on n'est pas en mode sélection et qu'on ne clique pas sur un bouton, le lien par défaut de la carte fonctionnera.
        });

        container.addEventListener('pointerdown', (e) => {
            const card = e.target.closest('.post-card');
            if (card && !e.target.closest('.post-actions')) { // Ne pas déclencher sur les boutons
                window.pressTimer = window.setTimeout(() => {
                    if (!isSelectionMode) enterSelectionMode();
                    const postId = parseInt(card.dataset.postId, 10);
                    if (!selectedPostIds.has(postId)) {
                        selectedPostIds.add(postId);
                        card.classList.add('selected');
                        updateMainActionsMenu();
                    }
                }, 800); // 800ms pour un appui long
            }
        });
        container.addEventListener('pointerup', () => clearTimeout(window.pressTimer));
        container.addEventListener('pointerleave', () => clearTimeout(window.pressTimer));
    }

    if (mainActionsButton && mainActionsDropdown) {
        mainActionsButton.addEventListener('click', (e) => {
            e.stopPropagation();
            mainActionsDropdown.classList.toggle('show');
        });
        document.addEventListener('click', (e) => {
            if (!mainActionsButton.contains(e.target) && !mainActionsDropdown.contains(e.target)) {
                mainActionsDropdown.classList.remove('show');
            }
        });
    }

    async function loadMyPosts() {
        try {
            const response = await fetch('/api/posts/my_posts');
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();

            if (data.success) {
                allPosts = data.posts || [];
                renderMyPosts(allPosts);
                updateMainActionsMenu();
            } else {
                displayMessage(data.message || _('Failed to load your ads.'), 'error');
            }
        } catch (error) {
            console.error('Load my posts error:', error);
            displayMessage(_('An error occurred while loading your ads.'), 'error');
            if(container) container.innerHTML = `<p>${_('Failed to load your ads.')}</p>`;
        }
    }

    // NOUVELLE FONCTION : Rendu des posts (adapté de posts.js)
    function renderMyPosts(posts) {
        if (!container) return;
        container.innerHTML = '';
        if (posts.length === 0) {
            container.innerHTML = `<p class="empty-message">${_("You haven't posted any ads yet. Time to create your first one!")}</p>`;
            return;
        }

        posts.forEach(post => {
            const visibilityClass = post.is_visible ? '' : 'hidden-post'; // Utiliser une classe qui n'est pas "hidden" pour ne pas faire display:none
            const toggleText = post.is_visible ? _('Hide') : _('Show');
            const toggleIcon = post.is_visible ? 'fa-eye' : 'fa-eye-slash';
            
            // ### DÉBUT DE LA MODIFICATION ###
            // On enlève les boutons superposés et on crée un bloc .post-actions en bas
            const postCardHTML = `
                <div class="post-card ${visibilityClass}" data-post-id="${post.id}">
                    <a href="/posts/${post.id}" class="post-card-link">
                        ${post.cover_image_url ? `<div class="post-card-image" style="background-image: url('${post.cover_image_url}');"></div>` : ''}
                        <div class="post-card-content">
                            <span class="post-card-category category-${String(post.category).toLowerCase()}">${post.category}</span>
                            <h3>${post.title}</h3>
                            <p>${post.description.substring(0, 100)}...</p>
                        </div>
                    </a>
                    
                    <div class="post-actions">
                        <a href="/edit_post/${post.id}" class="post-action-btn edit" title="${_('Edit')}">
                            <i class="fa-solid fa-pen-to-square"></i> ${_('Edit')}
                        </a>
                        <button class="post-action-btn toggle-visibility-button" title="${toggleText}">
                            <i class="fa-solid ${toggleIcon}"></i> ${toggleText}
                        </button>
                        <button class="post-action-btn delete delete-button" title="${_('Delete')}">
                            <i class="fa-solid fa-trash"></i> ${_('Delete')}
                        </button>
                    </div>
                    </div>
            `;
            // ### FIN DE LA MODIFICATION ###

            container.insertAdjacentHTML('beforeend', postCardHTML);
        });
    }
    
    // Fonction utilitaire pour afficher des messages (si elle n'existe pas déjà)
    function displayMessage(message, type = 'info') {
        const container = document.getElementById('message-container');
        if (container) {
            const msgDiv = document.createElement('div');
            msgDiv.className = `message ${type}`;
            msgDiv.textContent = message;
            container.innerHTML = ''; // Vide les anciens messages
            container.appendChild(msgDiv);
            setTimeout(() => {
                msgDiv.style.opacity = '0';
                setTimeout(() => msgDiv.remove(), 500);
            }, 5000);
        }
    }
    
    loadMyPosts();
});