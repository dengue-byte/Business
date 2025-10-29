// static/js/guest_nav.js

document.addEventListener('DOMContentLoaded', () => {
    // --- Gestion de la modale "À propos" ---
    const aboutButton = document.getElementById('about-button');
    const aboutModal = document.getElementById('about-modal');

    if (aboutButton && aboutModal) {
        const closeModalBtn = aboutModal.querySelector('.close-modal-btn');

        aboutButton.addEventListener('click', () => {
            aboutModal.classList.remove('hidden');
        });

        closeModalBtn.addEventListener('click', () => {
            aboutModal.classList.add('hidden');
        });

        aboutModal.addEventListener('click', (e) => {
            if (e.target === aboutModal) {
                aboutModal.classList.add('hidden');
            }
        });
    }

    // --- Gestion du menu de langue ---
    const langMenuButton = document.querySelector('.language-menu-button');
    const langMenuDropdown = document.querySelector('.language-menu-dropdown');
    const langSelectors = document.querySelectorAll('.lang-selector');

    if (langMenuButton && langMenuDropdown) {
        langMenuButton.addEventListener('click', (e) => {
            e.stopPropagation();
            langMenuDropdown.classList.toggle('active');
        });

        document.addEventListener('click', () => {
            if (langMenuDropdown.classList.contains('active')) {
                langMenuDropdown.classList.remove('active');
            }
        });
    }

    if (langSelectors) {
        langSelectors.forEach(selector => {
            selector.addEventListener('click', async (e) => {
                e.preventDefault();
                const lang = e.target.dataset.lang;
                
                // Crée un formulaire en mémoire pour envoyer la langue
                const form = document.createElement('form');
                form.method = 'POST';
                form.action = '/select-language';

                const input = document.createElement('input');
                input.type = 'hidden';
                input.name = 'language';
                input.value = lang;
                form.appendChild(input);

                document.body.appendChild(form);
                form.submit();
            });
        });
    }
});