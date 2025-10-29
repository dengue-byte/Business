// static/js/nav_active.js (Version corrigée et unifiée)

document.addEventListener('DOMContentLoaded', () => {
    // Normalise le chemin de l'URL pour une comparaison fiable
    // Exemple : "/posts/123/" devient "/posts"
    const currentPath = window.location.pathname;

    // Sélectionne TOUS les liens de navigation, PC et mobile
    const navItems = document.querySelectorAll('.desktop-nav-item:not(.nav-create-post), .mobile-nav-item:not(.create)');

    let isAnyLinkActive = false;

    navItems.forEach(item => {
        const itemHref = new URL(item.href).pathname;

        // Condition de correspondance simple mais efficace :
        // Si le chemin actuel COMMENCE par le chemin du lien (sauf pour la racine)
        // Ex: /posts/123 commence par /posts -> Le lien "Annonces" sera actif.
        if ( (itemHref !== '/' && currentPath.startsWith(itemHref)) || (itemHref === '/' && currentPath === '/') ) {
            item.classList.add('active');
            isAnyLinkActive = true;
        } else {
            item.classList.remove('active');
        }
    });

    // Si aucun lien ne correspond (ex: page d'accueil avec chemin vide), on active manuellement le lien "Home"
    if (!isAnyLinkActive) {
        document.querySelectorAll('a[href="/"]').forEach(homeLink => {
            if (homeLink.classList.contains('desktop-nav-item') || homeLink.classList.contains('mobile-nav-item')) {
                 homeLink.classList.add('active');
            }
        });
    }
});