// static/js/post_detail.js (Version complète et corrigée)

document.addEventListener('DOMContentLoaded', () => {
    const container = document.querySelector('.post-detail-container');
    const currentUserId = localStorage.getItem('user_id');

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
            console.error(_('Error adding/removing favorite:'), error);
        }
    }

    async function fetchPostDetails() {
        displayMessage(_('Loading...'), 'info');
        try {
            const response = await fetch(`/api/posts/${POST_ID}`);
            const data = await response.json();
            document.getElementById('message-container').innerHTML = '';
            
            if (data.success) {
                renderPost(data.post);
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            console.error(error);
            displayMessage(_('Network error.'), 'error');
        }
    }

    // dans static/js/post_detail.js
// Remplacez votre fonction renderPost existante par celle-ci :

// DANS static/js/post_detail.js
// REMPLACEZ toute l'ancienne fonction renderPost par celle-ci :

// DANS static/js/post_detail.js
// REMPLACEZ toute l'ancienne fonction renderPost par celle-ci :

function renderPost(post) {
    const favoritedClass = post.is_favorited ? 'favorited' : '';

    let imagesHTML = '';
    const imageCount = post.image_urls ? post.image_urls.length : 0;

    if (imageCount > 0) {
        // Le conteneur principal a maintenant un ID "lightgallery"
        // Chaque image est maintenant un lien <a> qui pointe vers l'image en haute résolution
        imagesHTML = `
            <div id="lightgallery" class="photo-grid" data-count="${imageCount}">
                ${post.image_urls.map(url => `
                    <a href="${url}">
                        <img src="${url}" alt="Ad image">
                    </a>
                `).join('')}
            </div>
        `;
    }

    const locationsDetailHTML = post.locations && post.locations.length > 0 ? `
        <div class="post-detail-location">
            <i class="fa-solid fa-map-marker-alt"></i>
            <strong>${post.locations.join(' / ')}</strong>
        </div>
    ` : '';

    container.innerHTML = `
        <div class="post-detail-image-container">
            ${imagesHTML}
            <button class="favorite-btn ${favoritedClass}" data-post-id="${post.id}" title="Save">
                <svg width="24" height="24" viewBox="0 0 24 24"><path d="M17 3H7c-1.1 0-2 .9-2 2v16l7-3 7 3V5c0-1.1-.9-2-2-2z"></path></svg>
            </button>
        </div>
        <div class="post-detail-content">
            <div class="post-detail-header"><h1>${post.title}</h1><span class="post-card-category">${post.category}</span></div>
            <div class="post-detail-meta">
                <span>Published by <strong><a href="/profile/${post.author_username}?from_post=${post.id}">${post.author_username}</a></strong> on ${new Date(post.timestamp).toLocaleDateString()}</span>
                ${locationsDetailHTML} </div>
            <p class="post-detail-description">${post.description.replace(/\n/g, '<br>')}</p>
            <div id="contact-section"></div>
        </div>
    `;
    
    // --- NOUVELLE LIGNE MAGIQUE ---
    // On active la LightGallery sur notre conteneur d'images
    const gallery = document.getElementById('lightgallery');
    if (gallery) {
        lightGallery(gallery);
    }

    renderContactButton(post.user_id);
    
    const favoriteBtn = container.querySelector('.favorite-btn');
    if (favoriteBtn) {
        favoriteBtn.addEventListener('click', () => {
             toggleFavorite(post.id, favoriteBtn);
        });
    }
}
    function renderContactButton(authorId) {
        const contactSection = document.getElementById('contact-section');
        if (!currentUserId) {
            contactSection.innerHTML = `<p>You must be <a href="/login">logged in</a> to contact the author.</p>`;
        } else if (currentUserId === String(authorId)) {
            contactSection.innerHTML = `<p>This is your ad. You can <a href="/edit_post/${POST_ID}">edit it here</a>.</p>`;
        } else {
            const button = document.createElement('button');
            button.id = 'chat-button';
            button.className = 'button-primary';
            button.textContent = _('Contact via Message');
            button.dataset.authorId = authorId;
            contactSection.appendChild(button);
            button.addEventListener('click', startChat);
        }
    }

    // DANS static/js/post_detail.js, REMPLACEZ la fonction startChat

async function startChat(event) {
    const participantId = event.target.dataset.authorId;
    displayMessage(_('Starting chat...'), 'info');
    try {
        const response = await fetch('/api/chat/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': window.getCsrfToken()
            },
            // On envoie maintenant l'ID de l'annonce en plus de l'ID de l'auteur
            body: JSON.stringify({ 
                participant_id: participantId,
                post_id: POST_ID // POST_ID est déjà défini dans ce fichier
            })
        });
        const data = await response.json();
        if (data.success) {
            window.location.href = `/messages?chatroom_id=${data.chatroom_id}`;
        } else {
            throw new Error(data.message);
        }
    } catch (error) {
        displayMessage(error.message || _("Error creating chat."), 'error');
    }
}
    fetchPostDetails();
});