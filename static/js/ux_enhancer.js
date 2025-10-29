document.addEventListener('DOMContentLoaded', () => {

    // --- GESTION DU PRELOADER ---
    const preloader = document.getElementById('preloader');

    // Cacher le preloader initial
    if (preloader) {
        window.addEventListener('load', () => {
            preloader.classList.add('hidden');
        });
    }

    // Afficher le preloader lors de la navigation
    document.body.addEventListener('click', (e) => {
        const link = e.target.closest('a');
        if (link) {
            const href = link.getAttribute('href');
            const target = link.getAttribute('target');
            // Condition pour ne pas déclencher sur les liens externes, les ancres, ou les actions JS
            if (href && (href.startsWith('/') || href.startsWith(window.location.origin)) && target !== '_blank' && !href.startsWith('#')) {
                // Ne pas déclencher pour les boutons d'action rapide comme les favoris
                if (!link.classList.contains('favorite-btn') && !link.closest('.no-loader')) {
                    if (preloader) {
                        preloader.classList.remove('hidden');
                    }
                }
            }
        }
    });
    window.addEventListener('pageshow', (event) => {
        if (event.persisted && preloader) {
            preloader.classList.add('hidden');
        }
    });

    // --- GESTION DU BOUTON "RETOUR EN HAUT" ---
    const backToTopButton = document.getElementById('back-to-top');

    if (backToTopButton) {
        window.addEventListener('scroll', () => {
            if (window.scrollY > 300) {
                backToTopButton.classList.add('show');
            } else {
                backToTopButton.classList.remove('show');
            }
        });

        backToTopButton.addEventListener('click', () => {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
    const imageModal = document.getElementById('image-viewer-modal');
    const alertModal = document.getElementById('alert-modal');
    const modalImageContent = document.getElementById('modal-image-content');
    const alertModalText = document.getElementById('alert-modal-text');

    // Fonction pour ouvrir une modale
    const openModal = (modal) => {
        if(modal) modal.classList.remove('hidden');
    };

    // Fonction pour fermer TOUTES les modales
    const closeModal = () => {
        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.classList.add('hidden');
        });
    };

    // --- Écouteurs d'événements pour les clics ---
   // DANS static/js/ux_enhancer.js

// --- Écouteurs d'événements pour les clics (VERSION CORRIGÉE) ---
// DANS static/js/ux_enhancer.js

// --- Écouteurs d'événements pour les clics (VERSION FINALE CORRIGÉE) ---
// DANS static/js/ux_enhancer.js

// --- Écouteurs d'événements pour les clics (VERSION FINALE AVEC LOGIQUE PROPRIÉTAIRE) ---
document.body.addEventListener('click', (e) => {
    const alertModal = document.getElementById('alert-modal');
    if (!alertModal) return;

    // Clic sur une photo de profil dans une carte
    const avatarLink = e.target.closest('.author-avatar-link');
    if (avatarLink) {
        // ... (le code pour la modale photo reste le même)
        e.preventDefault();
        e.stopPropagation();
        const imageUrl = avatarLink.dataset.imgUrl;
        if (imageUrl && modalImageContent) {
            modalImageContent.src = imageUrl;
            openModal(imageModal);
        }
    }

     const interactiveItem = e.target.closest('.interactive-footer-item');
    if (interactiveItem) {
        e.stopPropagation();

        const message = interactiveItem.dataset.message;
        const authorId = interactiveItem.dataset.authorId;
        const postId = interactiveItem.dataset.postId;
        const currentUserId = document.body.dataset.userId;

        const alertModal = document.getElementById('alert-modal');
        const alertModalText = document.getElementById('alert-modal-text');
        const alertModalActions = document.getElementById('alert-modal-actions');

        if (message && alertModalText && alertModalActions) {
            alertModalText.textContent = message;
            alertModalActions.innerHTML = ''; // On vide les actions précédentes
            alertModalActions.classList.remove('center-actions'); // On retire la classe de centrage

            const isOwner = authorId && currentUserId && authorId === currentUserId;

            // Si ce n'est pas notre annonce, on ajoute le bouton "Contacter"
            if (authorId && postId && !isOwner) {
                const contactButton = document.createElement('button');
                contactButton.id = 'modal-contact-btn';
                contactButton.className = 'button-primary';
                // AJOUT DE L'ICÔNE ICI
                contactButton.innerHTML = `<i class="fa-solid fa-comment-dots"></i> ${ _('Contact by message') }`;
                contactButton.dataset.authorId = authorId;
                contactButton.dataset.postId = postId;
                alertModalActions.appendChild(contactButton);
            }

            // On ajoute toujours le bouton "OK"
            const okButton = document.createElement('button');
            okButton.className = 'button-secondary close-modal-btn-styled';
            okButton.textContent = _('OK');
            alertModalActions.appendChild(okButton);
            
            // Si le conteneur n'a qu'un seul bouton (le bouton "OK"), on le centre
            if (alertModalActions.childElementCount === 1) {
                alertModalActions.classList.add('center-actions');
            }

            openModal(alertModal);
        }
    }
    
    // Clic sur le bouton de contact DANS la modale
    const contactBtn = e.target.closest('#modal-contact-btn');
    if (contactBtn) {
        const authorId = contactBtn.dataset.authorId;
        const postId = contactBtn.dataset.postId;
        closeModal();
        handleStartChat(authorId, postId);
    }

    // Clic sur un bouton de fermeture ou sur le fond de la modale
    if (e.target.classList.contains('close-modal-btn') || e.target.classList.contains('close-modal-btn-styled') || e.target.classList.contains('modal-overlay')) {
        closeModal();
    }
});

async function handleStartChat(authorId, postId) {
    const csrfToken = window.getCsrfToken();
    if (!csrfToken) {
        window.location.href = '/login';
        return;
    }
    
    try {
        const response = await fetch('/api/chat/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': csrfToken
            },
            body: JSON.stringify({
                participant_id: authorId,
                post_id: postId // On envoie l'ID du post
            })
        });
        const data = await response.json();
        if (data.success) {
            // Redirige vers la page de messagerie avec la bonne conversation
            window.location.href = `/messages?chatroom_id=${data.chatroom_id}`;
        } else {
            console.error('Failed to start chat:', data.message);
        }
    } catch (error) {
        console.error('Error starting chat:', error);
    }
}

    // Ajout d'un style pour le curseur sur les éléments interactifs
    const style = document.createElement('style');
    style.innerHTML = `.interactive-footer-item, .author-avatar-link { cursor: pointer; }`;
    document.head.appendChild(style);
});