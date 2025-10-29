// static/js/favorites.js (Version avec menu d'actions)

document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('favorites-list-container');
    const actionsMenu = document.querySelector('.actions-menu');
    const actionsButton = document.querySelector('.actions-button');
    const actionsDropdown = document.querySelector('.actions-dropdown');
    const clearFavoritesButton = document.getElementById('clear-favorites-button');
    let page = 1;
    let hasMore = true;
    let isLoading = false;

    async function toggleFavorite(postId, buttonElement) {
        const csrfToken = window.getCsrfToken();
        if (!csrfToken) {
            window.location.href = '/login';
            return;
        }
        try {
            const response = await fetch(`/api/posts/${postId}/favorite`, {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': csrfToken }
            });
            const data = await response.json();
            if (data.success && data.status === 'removed') {
                buttonElement.closest('.post-card').remove();
                if (container.children.length === 0) {
                    container.innerHTML = "<p>" + _("You have no ad in your favorites.") + "</p>";
                }
            }
        } catch (error) {
            console.error(_("Error removing favorite:"), error);
        }
    }
    
    container.addEventListener('click', async (event) => {
        const favoriteBtn = event.target.closest('.favorite-btn');
        if (favoriteBtn) {
            event.preventDefault(); 
            const postId = favoriteBtn.dataset.postId;
            toggleFavorite(postId, favoriteBtn);
        }
    });

    async function fetchFavorites() {
        if (!hasMore || isLoading) return;
        isLoading = true;
        if (page === 1) displayMessage(_('Loading...'), 'info');

        const url = new URL('/api/favorites', window.location.origin);
        url.searchParams.append('page', page);

        try {
            const response = await fetch(url, { headers: { 'X-CSRF-TOKEN': window.getCsrfToken() } });
            if (response.status === 401) { window.location.href = '/login'; return; }
            const data = await response.json();
            
            if (page === 1) document.getElementById('message-container').innerHTML = '';

            if (data.success) {
                renderPosts(data.posts);
                hasMore = data.has_next;
                page++;
                if (!hasMore && container.children.length === 0) {
                     container.innerHTML = "<p>" + _("You have no ad in your favorites.") + "</p>";
                }
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            displayMessage(_('Network error.'), 'error');
        } finally {
            isLoading = false;
        }
    }

    // REMPLACEZ la fonction renderPosts dans posts.js, home.js, et favorites.js

// REMPLACEZ la fonction renderPosts dans vos 3 fichiers JS par celle-ci

// REMPLACEZ la fonction renderPosts dans vos 3 fichiers JS (home.js, posts.js, favorites.js) par celle-ci

function renderPosts(posts) {
    // Si la page est la première et qu'il n'y a aucun post, on affiche un message.
    if (posts.length === 0 && page === 1) { // 'page' doit être défini dans le scope de chaque fichier
        const container = document.getElementById('posts-list-container') || document.getElementById('favorites-list-container');
        if(container) container.innerHTML = '<p>' + _("No ad found.") + '</p>';
        return;
    }

    posts.forEach(post => {
        const container = document.getElementById('posts-list-container') || document.getElementById('favorites-list-container');
        if (!container) return;
        
        const favoritedClass = post.is_favorited ? 'favorited' : '';
        let authorAvatarHTML = post.author_photo_url ?
            `<a href="#" class="author-avatar-link" data-img-url="${post.author_photo_url}" title="${_('View photo')}"><img src="${post.author_photo_url}" class="author-photo-small"></a>` :
            `<div class="author-initial-small">${post.author_username.charAt(0).toUpperCase()}</div>`;

        // *** LA MODIFICATION EST ICI ***
        // On ajoute le paramètre ?from_post=${post.id} au lien du profil
        const profileLink = `/profile/${post.author_username}?from_post=${post.id}`;
        const locationsHTML = post.locations && post.locations.length > 0 ? `
            <div class="post-card-location">
                <i class="fa-solid fa-map-marker-alt"></i>
                <span>${post.locations.join(', ')}</span>
            </div>
        ` : '';

        const postCardHTML = `
            <div class="post-card">
                <button class="favorite-btn ${favoritedClass}" data-post-id="${post.id}" title="${_('Save')}">
                    <svg width="24" height="24" viewBox="0 0 24 24"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z"></path></svg>
                </button>
                <a href="/posts/${post.id}" class="post-card-link">
                    ${post.cover_image_url ? `<div class="post-card-image" style="background-image: url('${post.cover_image_url}');"></div>` : ''}
                    <div class="post-card-content">
                        <span class="post-card-category category-${post.category.toLowerCase()}">${post.category}</span>
                        <h3>${post.title}</h3>
                        ${locationsHTML} 
                    </div>
                </a>
                <div class="post-card-footer-new">
                    <div class="footer-left">
                        ${authorAvatarHTML}
                        <a href="${profileLink}" title="${_('View profile')}">${post.author_username}</a>
                    </div>
                    <div class="footer-center interactive-footer-item" 
     data-message="${_('%(count)s people interact with this ad.', {count: post.interest_count})}" 
     data-author-id="${post.user_id}" 
     data-post-id="${post.id}" 
     title="${_('View interactions')}">
                        <i class="fa-solid fa-comments"></i>
                        <span>${post.interest_count}</span>
                    </div>
                    <div class="footer-right interactive-footer-item" data-message="${_('This ad has been viewed %(count)s times.', {count: post.view_count})}" title="${_('View views')}">
                        <i class="fa-solid fa-eye"></i>
                        <span>${post.view_count}</span>
                    </div>
                </div>
            </div>
        `;
        container.insertAdjacentHTML('beforeend', postCardHTML);
    });
}

    window.addEventListener('scroll', () => {
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 200) {
            fetchFavorites();
        }
    });

    // --- GESTION DU MENU D'ACTIONS ---
    actionsButton.addEventListener('click', (event) => {
        event.stopPropagation();
        actionsDropdown.classList.toggle('show');
    });

    clearFavoritesButton.addEventListener('click', async () => {
        if (confirm(_('Are you sure you want to clear your favorites list? This action is irreversible.'))) {
            try {
                const response = await fetch('/api/favorites/clear', {
                    method: 'POST',
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() }
                });
                const data = await response.json();
                if (data.success) {
                    container.innerHTML = "<p>" + _("Your favorites list has been cleared.") + "</p>";
                } else {
                    displayMessage(data.message, 'error');
                }
            } catch (error) {
                displayMessage(_('Network error during deletion.'), 'error');
            } finally {
                actionsDropdown.classList.remove('show');
            }
        }
    });

    document.addEventListener('click', () => {
        if (actionsDropdown.classList.contains('show')) {
            actionsDropdown.classList.remove('show');
        }
    });

    fetchFavorites();
});