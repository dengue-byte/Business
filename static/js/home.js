// static/js/home.js (Version avec redirection)

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search-input');
    const container = document.getElementById('posts-list-container');

    // On transforme la barre de recherche en bouton de redirection
    if (searchInput) {
        // On écoute le 'focus' qui est plus universel que le clic pour un input
        searchInput.addEventListener('focus', (event) => {
            // On empêche le clavier d'apparaître sur mobile inutilement
            event.target.blur(); 
            // On redirige vers la page des annonces avec un paramètre spécial
            window.location.href = '/posts?focus_search=true';
        });
    }

    // La logique pour les favoris reste la même
    if (container) {
        container.addEventListener('click', async (event) => {
            const favoriteBtn = event.target.closest('.favorite-btn');
            if (favoriteBtn) {
                event.preventDefault(); 
                const postId = favoriteBtn.dataset.postId;
                toggleFavorite(postId, favoriteBtn);
            }
        });
    }
});

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
