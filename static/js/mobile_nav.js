// DANS static/js/mobile_nav.js

document.addEventListener('DOMContentLoaded', () => {
    // --- Gestion du Menu Utilisateur ---
    const userMenuButton = document.querySelector('.user-menu-button');
    const userMenuDropdown = document.querySelector('.user-menu-dropdown');

    if (userMenuButton && userMenuDropdown) {
        userMenuButton.addEventListener('click', (event) => {
            event.stopPropagation();
            userMenuDropdown.classList.toggle('active');
        });

        document.addEventListener('click', () => {
            if (userMenuDropdown.classList.contains('active')) {
                userMenuDropdown.classList.remove('active');
            }
        });
    }

    // --- NOUVEAU : Gestion de la barre de recherche ---
    const searchContainer = document.querySelector('.search-container');
    const searchIconBtn = document.getElementById('search-icon-btn');
    const searchInput = document.getElementById('search-input-header');

    if (searchIconBtn && searchContainer && searchInput) {
        searchIconBtn.addEventListener('click', (event) => {
    event.preventDefault();
    searchContainer.classList.toggle('active');
    if (searchContainer.classList.contains('active')) {
        searchInput.focus();
        // AJOUT : Animation pour éloigner
        searchIconBtn.style.transition = 'transform 0.3s ease';
        searchIconBtn.style.transform = 'translateX(-0px)'; // Ajustez la valeur pour l'espace du input
    } else {
        searchIconBtn.style.transform = 'translateX(0)';
    }
});

        // Optionnel : Ferme la recherche si on clique ailleurs
        document.addEventListener('click', (event) => {
            if (!searchContainer.contains(event.target) && searchContainer.classList.contains('active')) {
                searchContainer.classList.remove('active');
            }
        });
    }
});