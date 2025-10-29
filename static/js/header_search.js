// DANS static/js/header_search.js

document.addEventListener('DOMContentLoaded', () => {
    const searchIconButton = document.getElementById('search-icon-btn');

    if (searchIconButton) {
        searchIconButton.addEventListener('click', (event) => {
            // Empêche le menu de se dérouler ou toute autre action par défaut
            event.preventDefault(); 
            // *** LA LIGNE MAGIQUE À AJOUTER ***
            event.stopPropagation(); // Empêche l'événement de "remonter" et d'activer d'autres menus
            
            // Si on est déjà sur la page des annonces...
            if (window.location.pathname === '/posts') {
                // ...on donne simplement le focus au champ de recherche de la page.
                document.getElementById('search-input')?.focus();
            } else {
                // Sinon, on redirige vers la page des annonces avec le paramètre magique.
                window.location.href = '/posts?focus_search=true';
            }
        });
    }
});