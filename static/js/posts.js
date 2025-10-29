// static/js/posts.js (Version finale avec async DOMContentLoaded et Choices pour filtre)

document.addEventListener('DOMContentLoaded', async () => {  // ← RENDU ASYNC
    const container = document.getElementById('posts-list-container');
    const searchInput = document.getElementById('search-input');
    const categoryNav = document.querySelector('.category-nav');
    const typeFilter = document.getElementById('type-filter');
    const sortFilter = document.getElementById('sort-filter');
    const locationFilter = document.getElementById('location-filter');  // Pour Choices
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('focus_search') === 'true' && searchInput) {
        searchInput.focus();
        // Optionnel : on nettoie l'URL pour ne pas garder le paramètre
        history.replaceState(null, '', window.location.pathname); 
    }

    // --- VARIABLES D'ÉTAT ---

    let currentType = '';
    let currentSort = 'newest';
    let currentCategory = '';
    let currentSearchTerm = '';
    let currentLocations = [];
    
    let page = 1;
    let hasMore = true;
    let isLoading = false;
    let searchTimeout;
    
    // Init Choices pour filtre location (multiple=true pour multi-sélection)
    let locationChoicesInstance = null;
    if (locationFilter) {
        try {
            locationChoicesInstance = await initAdvancedLocationSelector('location-filter', true);
            if (locationChoicesInstance) {
                locationChoicesInstance.passedElement.element.addEventListener('change', () => {
                    currentLocations = locationChoicesInstance.getValue(true).map(item => 
                        typeof item === 'object' ? item.value : item
                    );
                    loadInitialPosts();
                });
            }
        } catch (err) {
            console.error('Failed to init location filter:', err);
        }
    }

    // --- FONCTIONS PRINCIPALES ---

    async function loadInitialPosts() {
        page = 1;
        hasMore = true;
        container.innerHTML = '';
        displayMessage(_('Loading...'), 'info');
        await fetchAndRenderPosts();
        document.getElementById('message-container').innerHTML = '';
    }

    async function fetchAndRenderPosts() {
        if (!hasMore || isLoading) return;
        isLoading = true;
        
        const url = new URL('/api/posts', window.location.origin);
        url.searchParams.append('page', page);
        if (currentCategory) url.searchParams.append('category', currentCategory);
        if (currentSearchTerm) url.searchParams.append('search', currentSearchTerm);
        if (currentType) url.searchParams.append('type', currentType);
        if (currentSort) url.searchParams.append('sort', currentSort);
        // Mapper currentLocations vers params (strings)
        currentLocations.forEach(loc => url.searchParams.append('locations', loc));

        try {
            const response = await fetch(url);
            const data = await response.json();

            if (data.success) {
                renderPosts(data.posts);
                hasMore = data.has_next;
                page++;
                if (!hasMore && container.innerHTML === '') {
                     container.innerHTML = `<p>${_("No ad matches your search.")}</p>`;
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

    function renderPosts(posts) {
        // Si la page est la première et qu'il n'y a aucun post, on affiche un message.
        if (posts.length === 0 && page === 1) {
            const container = document.getElementById('posts-list-container') || document.getElementById('favorites-list-container');
            if(container) container.innerHTML = '<p>' + _("No ad found.") + '</p>';
            return;
        }

        posts.forEach(post => {
            const container = document.getElementById('posts-list-container') || document.getElementById('favorites-list-container');
            if (!container) return;
            
            const favoritedClass = post.is_favorited ? 'favorited' : '';
            let authorAvatarHTML = post.author_photo_url ?
                `<a href="#" class="author-avatar-link" data-img-url="${post.author_photo_url}" title="${_('View photo')}"><img src="${post.author_photo_url}" class="author-avatar" alt="Author"></a>` :
                `<div class="author-avatar default-avatar">${post.author_username[0].toUpperCase()}</div>`;
            
            const locationsHTML = post.locations && post.locations.length > 0 ?
                `<div class="post-card-location"><i class="fa-solid fa-map-marker-alt"></i><span>${post.locations.join(', ')}</span></div>` : '';
            
            const profileLink = `/profile/${post.author_username}`;
            
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
            if (data.success) {
                buttonElement.classList.toggle('favorited', data.status === 'added');
            }
        } catch (error) {
            console.error(_("Error adding/removing favorite:"), error);
        }
    }

    // --- ÉCOUTEURS D'ÉVÉNEMENTS ---

    // Scroll infini
    window.addEventListener('scroll', () => {
        if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 200) {
            fetchAndRenderPosts();
        }
    });

    // Recherche
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                currentSearchTerm = searchInput.value;
                loadInitialPosts();
            }, 500);
        });
    }

    // Filtres
    if (typeFilter) {
        typeFilter.addEventListener('change', () => {
            currentType = typeFilter.value;
            loadInitialPosts();
        });
    }
    if (sortFilter) {
        sortFilter.addEventListener('change', () => {
            currentSort = sortFilter.value;
            loadInitialPosts();
        });
    }

    // *** CORRECTION POUR LES CATÉGORIES ACTIVES ***
    if (categoryNav) {
        categoryNav.addEventListener('click', (e) => {
            const clickedButton = e.target.closest('.category-nav-item');
            if (!clickedButton) return;

            // 1. Retirer la classe 'active' de tous les boutons
            categoryNav.querySelectorAll('.category-nav-item').forEach(btn => {
                btn.classList.remove('active');
            });

            // 2. Ajouter la classe 'active' au bouton cliqué
            clickedButton.classList.add('active');

            // 3. Mettre à jour la catégorie et recharger les annonces
            currentCategory = clickedButton.dataset.category;
            loadInitialPosts();
        });
    }

    // Clic sur les boutons favoris (délégation d'événement)
    container.addEventListener('click', (event) => {
        const favoriteBtn = event.target.closest('.favorite-btn');
        if (favoriteBtn) {
            event.preventDefault(); 
            const postId = favoriteBtn.dataset.postId;
            toggleFavorite(postId, favoriteBtn);
        }
    });

    // --- SUPPRIMÉ populateFilters natif : Utilise Choices pour cohérence (déjà géré dans init)

    // Chargement initial
    loadInitialPosts();
});