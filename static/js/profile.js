// static/js/profile.js (Version mise à jour)

document.addEventListener('DOMContentLoaded', () => {

    const chatButton = document.getElementById('chat-button');
    const currentUserId = localStorage.getItem('user_id');

    if (chatButton) {
        // Logique pour masquer le bouton si c'est notre propre profil
        if (!currentUserId || chatButton.dataset.authorId === currentUserId) {
            chatButton.style.display = 'none';
        }

        // Écouteur de clic mis à jour
        chatButton.addEventListener('click', async (event) => {
            const button = event.target;
            const participantId = button.dataset.authorId;
            
            // *** NOUVELLE LIGNE ***
            // On récupère l'ID du post depuis l'attribut data-post-id (il peut être absent)
            const postId = button.dataset.postId; 

            displayMessage(_('Starting conversation...'), 'info');

            try {
                // On prépare le corps de la requête
                const requestBody = {
                    participant_id: participantId
                };

                // Si on a un postId, on l'ajoute au corps de la requête
                if (postId) {
                    requestBody.post_id = postId;
                }

                const response = await fetch('/api/chat/start', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': window.getCsrfToken()
                    },
                    body: JSON.stringify(requestBody)
                });

                const data = await response.json();
                if (data.success) {
                    window.location.href = `/messages?chatroom_id=${data.chatroom_id}`;
                } else {
                    throw new Error(data.message);
                }
            } catch (error) {
                displayMessage(error.message || _("Error creating conversation."), 'error');
            }
        });
    }

    // --- GESTION DE LA MODALE PHOTO (ne change pas) ---
    const photoModal = document.getElementById('photo-modal');
    const modalImage = document.getElementById('modal-image');
    const clickablePhoto = document.querySelector('.profile-photo-clickable');
    
    if (photoModal && modalImage && clickablePhoto) {
        clickablePhoto.addEventListener('click', () => {
            modalImage.src = clickablePhoto.src;
            photoModal.classList.remove('hidden');
        });
        const closeBtn = photoModal.querySelector('.close-modal-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => photoModal.classList.add('hidden'));
        }
        photoModal.addEventListener('click', (e) => {
            if (e.target === photoModal) photoModal.classList.add('hidden');
        });
    }
});