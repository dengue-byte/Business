// static/js/messages.js (Version fusionnée et mise à jour - 21/10/2025)
document.addEventListener('DOMContentLoaded', async () => {
    
    const chatContainer = document.querySelector('.chat-container');
    if (!chatContainer) return; // Sécurité si on n'est pas sur la bonne page

    // Variables de l'original (gardées)
    let currentUserId = localStorage.getItem('user_id');

    if (!currentUserId) {
        try {
            const response = await fetch('/api/user');
            const data = await response.json();
            if (data.success && data.user) {
                currentUserId = data.user.id;
                localStorage.setItem('user_id', currentUserId);
            } else {
                chatContainer.innerHTML = `<p style="padding: 2rem; text-align: center;">${_("Please log in to see your messages.")}</p>`;
                return;
            }
        } catch (error) {
            return;
        }
    }

    const socket = io();
    let currentChatroomId = null, otherParticipant = null, replyContext = null;
    
    // Variables de l'original (gardées pour la voix)
    let mediaRecorder, audioChunks = [], isRecording = false, timerInterval, seconds = 0;
    let audioContext, analyser, sourceNode, animationFrameId;
    let stream; 
    
    // Variables du nouveau code (modifiées)
    let typingTimer; // 'isTyping' a été enlevé par le nouveau code
    let selectionMode = false;
    const selectedMessages = new Set();
    
    // --- NOUVEAU : Gestion de l'historique de navigation pour le bouton "retour" ---
    window.addEventListener('popstate', (event) => {
        if (chatContainer.classList.contains('chat-view-active')) {
            // Si on est dans une discussion, le "retour" nous ramène à la liste
            event.preventDefault();
            exitChatView();
        }
    });

    const dom = {
        chatContainer,
        messageInputArea: document.getElementById('message-input-area'),
        chatroomsList: document.getElementById('chatrooms-list'),
        welcomeScreen: document.getElementById('chat-welcome-screen'),
        mainScreen: document.getElementById('chat-main-screen'),
        chatHeader: document.getElementById('current-chat-header'),
        messagesDisplay: document.getElementById('messages-display'),
        messageInput: document.getElementById('message-input'),
        micOrSendBtn: document.getElementById('mic-or-send-btn'),
        attachFileButton: document.getElementById('attach-file-button'),
        fileInput: document.getElementById('file-input'), // Gardé (même si le nouveau code ne l'utilise pas directement)
        cancelVoiceBtn: document.getElementById('cancel-voice-btn'),
        pauseResumeBtn: document.getElementById('pause-resume-btn'),
        voiceSendBtn: document.getElementById('voice-send-btn'),
        replyPreview: document.getElementById('reply-preview-container'),
        cancelReplyBtn: document.getElementById('cancel-reply-btn'),
        ratingModal: document.getElementById('rating-modal'),
        ratingForm: document.getElementById('rating-form'),
        // NOUVEAU: Éléments pour l'upload et les émojis (gardés de l'original)
        attachmentPopup: document.getElementById('attachment-popup'),
        galleryInput: document.getElementById('gallery-input'),
        cameraInput: document.getElementById('camera-input'),
        documentInput: document.getElementById('document-input'),
        emojiButton: document.getElementById('emoji-button'),
    };
    let emojiPickerVisible = false;
    let attachmentPopupVisible = false;


    // --- NOUVELLES FONCTIONS DE SÉLECTION (du nouveau code) ---
    function enterSelectionMode(messageId, wrapper) {
        selectionMode = true;
        dom.chatContainer.classList.add('selection-mode');
        toggleMessageSelection(messageId, wrapper); // Sélectionne le premier
    }

    function exitSelectionMode() {
        selectionMode = false;
        selectedMessages.clear();
        dom.chatContainer.classList.remove('selection-mode');
        dom.messagesDisplay.querySelectorAll('.message-wrapper.selected').forEach(el => el.classList.remove('selected'));
        updateHeaderForSelection(); // Appel de la nouvelle fonction
    }

    function toggleMessageSelection(messageId, wrapper) {
        if (selectedMessages.has(messageId)) {
            selectedMessages.delete(messageId);
            wrapper.classList.remove('selected');
        } else {
            selectedMessages.add(messageId);
            wrapper.classList.add('selected');
        }
        if (selectedMessages.size === 0) {
            exitSelectionMode();
        } else {
            updateHeaderForSelection();
        }
    }
    
    function formatLocalDateTime(isoString) {
    if (!isoString) return '';
    // Assure-toi que la chaîne est bien en UTC si 'Z' manque (sécurité)
    if (!isoString.endsWith('Z')) isoString += 'Z';
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return ''; // Gestion d'erreur si la date est invalide

    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    return `${hours}:${minutes}`;
}

    function updateHeaderForSelection() {
        if (!selectionMode) {
            if(otherParticipant) updateChatHeader(otherParticipant);
            return;
        }
        const count = selectedMessages.size;
        const canDelete = Array.from(selectedMessages).every(id => {
            const msgEl = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${id}']`);
            return msgEl && msgEl.classList.contains('sent');
        });

        dom.chatHeader.innerHTML = `
            <button class="chat-icon-button" id="cancel-selection-btn"><i class="fa-solid fa-times"></i></button>
            <strong class="selection-count">${count}</strong>
            <div class="selection-actions">
                <button class="chat-icon-button" id="copy-selection-btn" ${count !== 1 ? 'disabled' : ''}><i class="fa-solid fa-copy"></i></button>
                <button class="chat-icon-button" id="delete-selection-btn" ${!canDelete ? 'disabled' : ''}><i class="fa-solid fa-trash"></i></button>
            </div>
        `;
        addHeaderEventListeners();
    }

    // --- FONCTIONS DE MESSAGERIE (NOUVELLES du nouveau code) ---
    // Les fonctions addLocalMessage, updateLocalMessage, markAsFailed, retrySend, sendMessageLogic
    // ont été remplacées par cette nouvelle logique plus directe.

    function sendTextMessage() {
        const content = dom.messageInput.value.trim();
        if (!content && !replyContext) return; // Modifié: on peut envoyer une réponse sans texte
        
        const repliedToId = replyContext ? replyContext.messageId : null;
        // --- NOUVEAU : On récupère le contexte complet de la réponse pour l'affichage instantané ---
        const repliedToContext = replyContext;

        const tempId = 'temp-' + Date.now();
        displayMessageBubble({
            id: tempId,
            chatroom_id: currentChatroomId,
            sender_id: currentUserId,
            sender_username: _('Me'), // Corrigé de 'Me'
            content: content,
            timestamp: new Date().toISOString(),
            status: 'pending',
            replied_to: repliedToContext ? { id: repliedToId, content: repliedToContext.text, sender_username: repliedToContext.author } : null
        });
        scrollToBottom();

        socket.emit('new_message', {
            chatroom_id: currentChatroomId,
            content: content,
            replied_to_id: repliedToId
        }, (response) => {
            if (response && response.success) {
                // Utilise la nouvelle fonction de mise à jour
                updateMessageStatus(tempId, response.message_id, response.status);
            }
            // Note: Le nouveau code n'a pas de 'markAsFailed'
        });

        dom.messageInput.value = '';
        dom.messageInput.style.height = 'auto';
        hideReplyPreview();
        backToMicButton();
    }

    async function uploadAndSendFiles(files) {
        hideAllPopups();
        for (const file of files) {
            const formData = new FormData();
            
            // Logique de renommage de fichier de l'original (fusionnée)
            let filename = "file_upload";
            if (file.type && file.type.startsWith('audio/')) {
                const extension = file.type.split('/')[1].split(';')[0]; 
                filename = `voix.${extension}`;
            } else if (file.name) {
                filename = file.name;
            }
            formData.append('file', file, filename); 
            
            const tempId = 'temp-file-' + Date.now() + file.name;
            const fileURL = URL.createObjectURL(file); // Crée une URL locale pour l'aperçu

            displayMessageBubble({
                id: tempId,
                chatroom_id: currentChatroomId,
                sender_id: currentUserId,
                sender_username: _('Me'), // Corrigé de 'Me'
                file_url: fileURL,
                file_type: file.type,
                timestamp: new Date().toISOString(),
                status: 'pending',
                replied_to: replyContext ? { id: replyContext.messageId, content: replyContext.text, sender_username: replyContext.author } : null
            });
            scrollToBottom();
            
            const repliedToId = replyContext ? replyContext.messageId : null;
            hideReplyPreview(); // Cache l'aperçu après l'avoir utilisé

            try {
                const response = await fetch('/api/chat/upload', {
                    method: 'POST',
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: formData
                });
                const data = await response.json();
                if (!data.success) throw new Error(data.message);

                socket.emit('new_message', {
                    chatroom_id: currentChatroomId,
                    file_path: data.file_path, // le nouveau code utilise file_path
                    file_type: data.file_type, // le nouveau code utilise file_type
                    replied_to_id: repliedToId
                }, (response) => {
                    if (response && response.success) {
                        // Met à jour l'ID et le statut, et potentiellement l'URL si le serveur la renvoie
                        updateMessageStatus(tempId, response.message_id, response.status, response.file_url || null);
                    }
                });

            } catch (error) {
                console.error("Upload error:", error);
                // Note: Le nouveau code n'a pas de 'markAsFailed'
            }
        }
    }

    // --- Fonctions de gestion des conversations (NOUVELLES du nouveau code) ---
    async function loadChatrooms() {
        try {
            const response = await fetch('/api/chat/chatrooms');
            const data = await response.json();
            if (data.success) {
                renderChatrooms(data.chatrooms);
                // Garde la logique de l'original
                checkForInitialChatroom(data.chatrooms);
            }
        } catch (error) { console.error(_('Error loading conversations:'), error); }
    }

    // DANS messages.js (à ajouter après la fonction loadChatrooms)

async function deleteChatroom(chatroomId) {
        if (!confirm(_("Are you sure you want to delete this conversation? This action is irreversible."))) {
            return;
        }

        try {
            const response = await fetch(`/api/chat/chatroom/${chatroomId}`, {
                method: 'DELETE',
                headers: { 'X-CSRF-TOKEN': window.getCsrfToken() } // Assure-toi que getCsrfToken existe
            });
            const data = await response.json();
            if (data.success) {
                // Supprimer la conversation de l'interface
                const chatItem = dom.chatroomsList.querySelector(`.chat-list-item[data-chatroom-id="${chatroomId}"]`);
                if (chatItem) {
                    chatItem.remove();
                }
                // Si c'était la conversation active, on retourne à l'accueil
                if (currentChatroomId === chatroomId) {
                    exitChatView();
                }
            } else {
                alert(data.message || _("Error during deletion."));
            }
        } catch (error) {
            console.error("Delete chat error:", error);
            alert(_("A network error has occurred."));
        }
    }


// DANS : messages.js
// REMPLACEZ l'ancienne fonction renderChatrooms par celle-ci :

function renderChatrooms(chatrooms) {
    if (!dom.chatroomsList) return; // Gardé de l'original
    dom.chatroomsList.innerHTML = '';
    if (chatrooms.length === 0) {
        dom.chatroomsList.innerHTML = `<p class="empty-list-message">${_("No conversation.")}</p>`;
        return;
    }
    chatrooms.forEach(room => {
        const otherP = room.other_participant; // Raccourci du nouveau code
        if (!otherP) return;

        let avatarHTML = otherP.profile_photo
            ? `<img src="${otherP.profile_photo}" alt="${otherP.username}" class="avatar-img">`
            : `<div class="chat-item-avatar">${otherP.username.charAt(0).toUpperCase()}</div>`;
        
        // NOUVEAU: Titre de l'annonce
        const postTitleHTML = room.post_info ? `<span class="chat-item-post-title">${room.post_info.title}</span>` : '';

        let lastMsgContent = `<em>${_("Start the conversation!")}</em>`;
        let statusIcon = ''; // Gardé de l'original
        let lastMsgTime = ''; // Gardé de l'original

        if (room.last_message) {
            if (room.last_message.content) lastMsgContent = room.last_message.content;
            else if (room.last_message.file_type?.startsWith('image')) lastMsgContent = `📷 ${_('Photo')}`;
            else if (room.last_message.file_type?.startsWith('audio')) lastMsgContent = `🎤 ${_('Voice message')}`;
            else if (room.last_message.file_type?.startsWith('video')) lastMsgContent = `📹 ${_('Video')}`; // Ajout du nouveau code
            else lastMsgContent = `📎 ${_('Attached file')}`;
            
            // Logique de temps de l'original (gardée)
            let lastMsgTimestamp = room.last_message.timestamp;
            if (!lastMsgTimestamp.endsWith('Z')) lastMsgTimestamp += 'Z';
            const parsedDate = new Date(lastMsgTimestamp);
            lastMsgTime = formatLocalDateTime(lastMsgTimestamp);

            // Logique d'icône de statut de l'original (gardée)
            if (String(room.last_message.sender_id) === String(currentUserId)) {
                const statusClass = room.last_message.status === 'read' ? 'read' : 'sent';
                const iconClass = room.last_message.status === 'sent' ? 'fa-solid fa-check' : 'fa-solid fa-check-double';
                statusIcon = `<i class="chat-status-icon ${statusClass} ${iconClass}"></i>`;
            }
        }
        const roomDiv = document.createElement('div');
    roomDiv.className = 'chat-list-item';
    roomDiv.dataset.chatroomId = room.id;
    
    // =================================================================
    // --- MODIFICATION 1 : Remplacement du Menu par un Bouton Simple ---
    // =================================================================
    // L'ancien HTML avec le menu déroulant a été remplacé par ce bouton unique.
    roomDiv.innerHTML = `
        ${avatarHTML}
        <div class="chat-item-main">
            <div class="chat-item-top-row">
                <strong>${otherP.username}</strong>
                <span class="chat-item-time">${lastMsgTime}</span>
            </div>
            ${postTitleHTML} 
            <div class="chat-item-bottom-row">
                <p class="last-message-preview">${statusIcon}${lastMsgContent}</p> 
                ${room.unread_count > 0 ? `<div class="notification-badge">${room.unread_count}</div>` : ''}
            </div>
        </div>
         <div class="chatroom-actions">
             <button class="chat-icon-button delete-chatroom-btn" title="${_('Delete conversation')}" data-chatroom-id="${room.id}">
                <i class="fa-solid fa-trash"></i>
             </button>
         </div>
    `;

    roomDiv.addEventListener('click', (e) => {
            const deleteButton = e.target.closest('.delete-chatroom-btn');

            // Cas 1 : Clic sur le bouton "Supprimer"
            if (deleteButton) {
                e.stopPropagation(); // Empêche d'entrer dans la conversation
                const chatroomId = Number(deleteButton.dataset.chatroomId);
                deleteChatroom(chatroomId); // Appelle directly la suppression

            // Cas 2 : Clic sur l'item pour ouvrir la conversation
            } else if (!e.target.closest('.chatroom-actions')) {
                joinChatroom(room.id, otherP);
            }
        });

        dom.chatroomsList.appendChild(roomDiv);
    });
}
    function updateChatListItem(msg) {
        if (!dom.chatroomsList) return;

        const chatItem = dom.chatroomsList.querySelector(`.chat-list-item[data-chatroom-id="${msg.chatroom_id}"]`);
        if (!chatItem) return; // Si la conversation n'est pas dans la liste

        // Mise à jour du dernier message
        const lastMsgPreview = chatItem.querySelector('.last-message-preview');
        if (lastMsgPreview) {
            let lastMsgContent = '';
            if (msg.content) lastMsgContent = msg.content;
            else if (msg.file_type?.startsWith('image')) lastMsgContent = `📷 ${_('Photo')}`;
            else if (msg.file_type?.startsWith('audio')) lastMsgContent = `🎤 ${_('Voice message')}`;
            else if (msg.file_type?.startsWith('video')) lastMsgContent = `📹 ${_('Video')}`;
            else lastMsgContent = `📎 ${_('Attached file')}`;
            
            // On ajoute l'icône de statut si c'est notre message
            let statusIconHTML = '';
            if (String(msg.sender_id) === String(currentUserId)) {
                const iconClass = (msg.status === 'delivered' || msg.status === 'read') ? 'fa-solid fa-check-double' : 'fa-solid fa-check';
                statusIconHTML = `<i class="chat-status-icon ${msg.status} ${iconClass}"></i>`;
            }
            lastMsgPreview.innerHTML = `${statusIconHTML}${lastMsgContent}`;
        }

        // Mise à jour de l'heure
        const timeEl = chatItem.querySelector('.chat-item-time');
        if (timeEl) {
            timeEl.textContent = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }

        // Mettre la conversation en haut de la liste
        dom.chatroomsList.prepend(chatItem);
    }

    // --- Fonctions de gestion de la vue de discussion (NOUVELLES du nouveau code) ---
    function joinChatroom(chatroomId, participantData) {
        if (!participantData) return;
        // La vérification 'if (currentChatroomId === chatroomId ...)' a été retirée par le nouveau code
        
        // NOUVEAU : Gère l'historique du navigateur
        // Modifié pour ne pas ajouter si c'est déjà le bon
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('chatroom_id') !== chatroomId) {
            history.pushState({ chatroomId: chatroomId }, `Chat with ${participantData.username}`, `?chatroom_id=${chatroomId}`);
        }
        
        document.body.classList.add('in-chat-view');
        dom.chatContainer.classList.add('chat-view-active');
        exitSelectionMode(); // Gardé de l'original

        otherParticipant = participantData;
        currentChatroomId = chatroomId;
        socket.emit('join', { chatroom_id: chatroomId });

        document.querySelectorAll('.chat-list-item').forEach(item => item.classList.remove('active'));
        const activeItem = document.querySelector(`.chat-list-item[data-chatroom-id="${chatroomId}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
            activeItem.querySelector('.notification-badge')?.remove();
        }
        
        updateChatHeader(participantData);

        dom.welcomeScreen.classList.add('hidden'); // Gardé de l'original
        dom.mainScreen.classList.remove('hidden'); // Gardé de l'original
        // NOUVEAU: Spinner de chargement
        dom.messagesDisplay.innerHTML = `<div class="spinner-container"><div class="spinner"></div></div>`;
        
        dom.messageInput.value = ''; // Gardé de l'original
        backToMicButton(); // Gardé de l'original
    }

    // NOUVELLE FONCTION du nouveau code
    function exitChatView() {
        document.body.classList.remove('in-chat-view');
        dom.chatContainer.classList.remove('chat-view-active');
        currentChatroomId = null;
        otherParticipant = null;
        exitSelectionMode();
        // Gère l'historique
        history.pushState({ chatroomId: null }, 'Messages', '/messages');
        
        // Remet l'écran d'accueil (logique de l'original)
        document.querySelectorAll('.chat-list-item').forEach(item => item.classList.remove('active'));
        dom.mainScreen.classList.add('hidden');
        dom.welcomeScreen.classList.remove('hidden');
    }

    // NOUVELLE FONCTION du nouveau code
    function updateChatHeader(participantData) {
        let avatarHTML = participantData.profile_photo
            ? `<img src="${participantData.profile_photo}" alt="${participantData.username}" class="avatar-img">`
            : `<div class="chat-item-avatar">${participantData.username.charAt(0).toUpperCase()}</div>`;

        dom.chatHeader.innerHTML = `
            <button class="back-to-list-btn chat-icon-button"><i class="fa-solid fa-arrow-left"></i></button>
            <div class="chat-header-info">${avatarHTML}<div class="chat-header-text"><strong>${participantData.username}</strong><div id="activity-indicator"></div></div></div>
            <div class="chat-header-actions"><button class="rate-user-btn chat-icon-button" title="${_('Rate')}"><i class="fa-solid fa-star"></i></button></div>
        `;
        addHeaderEventListeners();
    }

    // NOUVELLE FONCTION du nouveau code (fusionne l'ancienne)
    function addHeaderEventListeners() {
        // Nouveau : utilise window.history.back() pour le bouton retour
        dom.chatHeader.querySelector('.back-to-list-btn')?.addEventListener('click', () => window.history.back());
        
        // Gardé : le bouton de notation
        dom.chatHeader.querySelector('.rate-user-btn')?.addEventListener('click', openRatingModal);
        
        // Nouveau : actions de sélection
        dom.chatHeader.querySelector('#cancel-selection-btn')?.addEventListener('click', exitSelectionMode);
        dom.chatHeader.querySelector('#copy-selection-btn')?.addEventListener('click', copySelectedMessages);
        dom.chatHeader.querySelector('#delete-selection-btn')?.addEventListener('click', deleteSelectedMessages);
    }

    
    function insertDateSeparatorIfNeeded(currentMessageTimestamp, lastMessageTimestamp) {
        // Si c'est le premier message, pas de séparateur avant
        if (!lastMessageTimestamp) return;

        const currentDate = new Date(currentMessageTimestamp);
        const lastDate = new Date(lastMessageTimestamp);

        // On compare uniquement le jour, le mois et l'année, pas l'heure
        if (currentDate.toDateString() !== lastDate.toDateString()) {
            const separator = document.createElement('div');
            separator.className = 'date-separator';
            
            const today = new Date();
            const yesterday = new Date();
            yesterday.setDate(today.getDate() - 1);
            
            let dateText = '';
            if (currentDate.toDateString() === today.toDateString()) {
                dateText = _('Today');
            } else if (currentDate.toDateString() === yesterday.toDateString()) {
                dateText = _('Yesterday');
            } else {
                // Format de date plus complet pour les jours plus anciens
                dateText = currentDate.toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
            }

            separator.innerHTML = `<span>${dateText}</span>`;
            dom.messagesDisplay.appendChild(separator);
        }
    }
    function displayMessageBubble(msg, lastMessageTimestamp = null) {
        // On insère le séparateur de date si nécessaire (pour la requête 2)
        insertDateSeparatorIfNeeded(msg.timestamp, lastMessageTimestamp);

        const isSentByMe = String(msg.sender_id) === String(currentUserId);
        const wrapper = document.createElement('div');
        wrapper.className = `message-wrapper ${isSentByMe ? 'sent' : 'received'}`;
        wrapper.dataset.messageId = msg.id;
        // On stocke le timestamp pour la logique du séparateur de date
        wrapper.dataset.timestamp = msg.timestamp; 
        
        let replyHTML = '';
        if (msg.replied_to) {
            let replyContent = msg.replied_to.content || `<em>${_('Media')}</em>`;
            if (replyContent.length > 70) replyContent = replyContent.substring(0, 70) + '...';
            replyHTML = `<div class="quoted-message"><strong>${msg.replied_to.sender_username}</strong><p>${replyContent}</p></div>`;
        }

        let contentHTML = '';
        if (msg.file_url) {
            // ... (le reste de la logique de contenu reste identique à ton code original)
            const fileType = msg.file_type || '';
            if (fileType.startsWith('image/')) {
                contentHTML = `<div class="message-content image-container"><img src="${msg.file_url}" class="chat-image" onload="if(this.src.startsWith('blob:')) URL.revokeObjectURL(this.src)" onclick="window.open('${msg.file_url}', '_blank')"></div>`;
            } else if (fileType.startsWith('video/')) {
                contentHTML = `<div class="message-content video-container"><video src="${msg.file_url}" class="chat-video" controls onload="if(this.src.startsWith('blob:')) URL.revokeObjectURL(this.src)"></video></div>`;
            } else if (fileType.startsWith('audio/')) {
                contentHTML = `<div class="message-content audio-container"><audio controls class="chat-audio" src="${msg.file_url}" onload="if(this.src.startsWith('blob:')) URL.revokeObjectURL(this.src)"></audio></div>`;
            } else {
                const fileName = msg.file_url.split('/').pop().split('_').slice(1).join('_') || _('File');
                contentHTML += `<a href="${msg.file_url}" target="_blank" class="chat-file-link"><i class="fa-solid fa-file"></i><span>${fileName}</span></a>`;
            }
        }
        if (msg.content) {
            contentHTML += `<div class="message-content text-content"><p>${msg.content.replace(/\n/g, '<br>')}</p></div>`;
        }
        
        let statusHTML = '';
        if (isSentByMe) {
            const statusClass = msg.status === 'read' ? 'read' : '';
            const iconClass = msg.status === 'pending' ? 'fa-regular fa-clock' : (msg.status === 'sent' ? 'fa-solid fa-check' : 'fa-solid fa-check-double');
            statusHTML = `<span class="message-status ${statusClass}" data-status="${msg.status}"><i class="${iconClass}"></i></span>`;
        }

        const time = formatLocalDateTime(msg.timestamp);

        wrapper.innerHTML = `
            <div class="message-bubble-container">
                <div class="message-bubble">${replyHTML}${contentHTML}</div>
                <div class="message-meta"><span>${time}</span>${statusHTML}</div>
            </div>`;
        
        dom.messagesDisplay.appendChild(wrapper);

        // --- CORRECTION DES ÉCOUTEURS D'ÉVÉNEMENTS ---
        let pressTimer = null;

    wrapper.addEventListener('pointerdown', (e) => {
        // Empêche le menu contextuel par défaut sur ordinateur
        if (e.pointerType === 'mouse') e.preventDefault();
        
        // Démarre le minuteur pour l'appui long
        pressTimer = setTimeout(() => {
            enterSelectionMode(msg.id, wrapper);
            pressTimer = null; // Réinitialise le timer pour éviter les conflits
        }, 500); // 500ms pour un appui long
    });

    const clearPressTimer = () => {
        if (pressTimer) {
            clearTimeout(pressTimer);
        }
    };
    
    // Si on lève le doigt ou si le curseur quitte la zone, on annule l'appui long
    wrapper.addEventListener('pointerup', clearPressTimer);
    wrapper.addEventListener('pointerleave', clearPressTimer);

    // Gère le CLIC SIMPLE
    wrapper.addEventListener('click', () => {
        if (selectionMode) {
            // Si on est en mode sélection, le clic sert à ajouter/retirer
            toggleMessageSelection(msg.id, wrapper);
        } else {
            // Sinon, le clic sert à répondre (citer)
            const contentForReply = msg.content || (msg.file_type ? _('Media') : '');
            showReplyPreview(msg.id, msg.sender_username, contentForReply);
        }
    });
}

    // --- Fonctions de mise à jour et actions (NOUVELLES) ---
    function updateMessageStatus(tempId, newId, status, newUrl = null) {
        const wrapper = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${tempId}']`);
        if (!wrapper) return;

        wrapper.dataset.messageId = newId;
        const statusEl = wrapper.querySelector('.message-status');
        if (statusEl) {
            const icon = statusEl.querySelector('i');
            statusEl.dataset.status = status; // Ajouté
            statusEl.className = `message-status ${status}`;
            // Logique d'icône mise à jour
            icon.className = status === 'sent' ? 'fa-solid fa-check' : (status === 'delivered' || status === 'read' ? 'fa-solid fa-check-double' : 'fa-regular fa-clock');
        }
        if (newUrl) {
            const mediaEl = wrapper.querySelector('img, video, audio');
            if (mediaEl) {
                mediaEl.src = newUrl;
                // Met à jour le lien cliquable pour les images
                const imgLink = mediaEl.closest('.image-container');
                if (imgLink) imgLink.querySelector('img').setAttribute('onclick', `window.open('${newUrl}', '_blank')`);
            }
        }
    }
    
    function copySelectedMessages() {
    if (selectedMessages.size !== 1) return;
    const msgId = selectedMessages.values().next().value;
    const msgEl = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${msgId}'] .text-content p`);
    
    if (msgEl && msgEl.innerText) {
        navigator.clipboard.writeText(msgEl.innerText)
            .catch(err => {
                console.error('Failed to copy text: ', err);
                // On peut ajouter un message d'erreur discret si besoin, mais pas de succès
            });
    }
    // On quitte le mode sélection que la copie ait réussi ou non
    exitSelectionMode();
}

    function deleteSelectedMessages() {
        if (confirm(_('Delete messages?'))) {
            socket.emit('delete_multiple_messages', { message_ids: Array.from(selectedMessages) });
        }
    }

    // --- Fonctions de réponse (Gardées de l'original) ---
    function showReplyPreview(messageId, author, content, type) {
        replyContext = { messageId, author, text: content };
        const replyContentEl = dom.replyPreview.querySelector('.reply-preview-content');
        if (!replyContentEl) return;

        dom.replyPreview.classList.remove('hidden');
        dom.messageInput.focus();

        replyContentEl.innerHTML = `
            <div class="reply-preview-inner quoted-message">
                <strong>${author}</strong>
                <p>${content.length > 70 ? content.substring(0, 70) + '...' : content}</p>
            </div>
        `;
    }

    function hideReplyPreview() {
        replyContext = null;
        if (dom.replyPreview) {
            dom.replyPreview.classList.add('hidden');
            const content = dom.replyPreview.querySelector('.reply-preview-content');
            if (content) content.innerHTML = '';
        }
    }

    // --- Fonctions des messages vocaux (Gardées de l'original, sauf resetVoiceUI) ---
    function formatTime(totalSeconds) {
        const minutes = Math.floor(totalSeconds / 60);
        const secondsVal = Math.floor(totalSeconds % 60);
        return `${minutes}:${secondsVal.toString().padStart(2, '0')}`;
    }
    async function startRecording() {
        if (isRecording) return;
        // La ligne 'socket.emit('user_recording_status'...)' a été retirée par le nouveau code
        try {
            stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            // La ligne 'socket.emit('user_recording_status'...)' a été retirée par le nouveau code
            document.querySelector('.input-mode-voice').classList.remove('hidden');
            isRecording = true;
            dom.messageInputArea.classList.add('recording-active');
            dom.messageInputArea.style.minHeight = '120px';
            
            seconds = 0;
            const timerEl = document.getElementById('record-timer');
            timerEl.textContent = '0:00';
            timerInterval = setInterval(() => {
                seconds++;
                timerEl.textContent = formatTime(seconds);
            }, 1000);
            
            audioChunks = [];
            mediaRecorder = new MediaRecorder(stream);
            mediaRecorder.ondataavailable = e => audioChunks.push(e.data);
            mediaRecorder.onstop = () => {
                if (audioChunks.length > 0) {
                    const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                    // Utilise la NOUVELLE fonction d'upload (pour un seul fichier)
                    uploadAndSendFiles([audioBlob]);
                }
            };

            audioContext = new (window.AudioContext || window.webkitAudioContext)();
            analyser = audioContext.createAnalyser();
            analyser.fftSize = 256;
            sourceNode = audioContext.createMediaStreamSource(stream);
            sourceNode.connect(analyser);
            
            mediaRecorder.start();
            drawWaveform();

        } catch (err) {
            console.error("Erreur d'enregistrement :", err);
            isRecording = false;
            dom.messageInputArea.classList.remove('recording-active');
            dom.messageInputArea.style.minHeight = 'var(--footer-height)';
        }
    }

    // NOUVELLE fonction resetVoiceUI (du nouveau code)
    function resetVoiceUI() {
        if(timerInterval) clearInterval(timerInterval); // Vérification ajoutée
        isRecording = false;
        if(animationFrameId) cancelAnimationFrame(animationFrameId); // Vérification ajoutée
        if (audioContext) audioContext.close();
        if (stream) { stream.getTracks().forEach(track => track.stop()); }
        
        // On s'assure de cacher l'UI vocale et de réinitialiser la hauteur
        document.querySelector('.input-mode-voice').classList.add('hidden');
        dom.messageInputArea.classList.remove('recording-active');
        dom.messageInput.style.height = 'auto'; // Réinitialise la hauteur du textarea
        handleInputChange(); // Ré-évalue s'il faut afficher le micro ou l'avion
        dom.messageInputArea.style.minHeight = 'var(--footer-height)'; // Ajouté pour forcer la réinitialisation
    }


    function stopAndSendRecording() {
        if (!isRecording || !mediaRecorder) return;
        // La ligne 'socket.emit('user_recording_status'...)' a été retirée par le nouveau code
        mediaRecorder.stop();
        resetVoiceUI();
    }

    function cancelRecording() {
        if (!isRecording || !mediaRecorder) return;
        // La ligne 'socket.emit('user_recording_status'...)' a été retirée par le nouveau code
        mediaRecorder.onstop = null;
        mediaRecorder.stop();
        resetVoiceUI();
    }

    function pauseOrResumeRecording() {
        if (!isRecording || !mediaRecorder) return;
        const pauseBtnIcon = dom.pauseResumeBtn?.querySelector('i');
        if (!pauseBtnIcon) return;

        if (mediaRecorder.state === 'recording') {
            mediaRecorder.pause();
            clearInterval(timerInterval);
            cancelAnimationFrame(animationFrameId);
            pauseBtnIcon.classList.remove('fa-pause');
            pauseBtnIcon.classList.add('fa-play');
        } else if (mediaRecorder.state === 'paused') {
            mediaRecorder.resume();
            const timerEl = document.getElementById('record-timer');
            timerInterval = setInterval(() => {
                seconds++;
                timerEl.textContent = formatTime(seconds);
            }, 1000);
            drawWaveform(); 
            pauseBtnIcon.classList.remove('fa-play');
            pauseBtnIcon.classList.add('fa-pause');
        }
    }

    function drawWaveform() {
        animationFrameId = requestAnimationFrame(drawWaveform);
        const dataArray = new Uint8Array(analyser.frequencyBinCount);
        analyser.getByteFrequencyData(dataArray);

        const waveformContainer = document.getElementById('waveform-container');
        if (!waveformContainer) return;
        waveformContainer.innerHTML = ''; 

        const barCount = 30; 

        for (let i = 0; i < barCount; i++) {
            const barHeight = Math.pow(dataArray[i * 2] / 255, 2) * 100;
            const bar = document.createElement('div');
            bar.className = 'waveform-bar';
            bar.style.height = `${Math.max(5, barHeight)}%`;
            waveformContainer.appendChild(bar);
        }
    }
    
    // --- Fonctions de notation (Gardées de l'original) ---
    function openRatingModal() {
        if (!otherParticipant || !dom.ratingModal) {
            console.error("ERREUR : La modale ne peut s'ouvrir. 'otherParticipant' ou 'dom.ratingModal' est manquant.");
            return;
        }
        const ratedUsernameEl = dom.ratingModal.querySelector('#rated-username');
        if (ratedUsernameEl) {
            ratedUsernameEl.textContent = otherParticipant.username;
        }
        dom.ratingModal.classList.remove('hidden');
    }
    
    function closeRatingModal() { if(dom.ratingModal) dom.ratingModal.classList.add('hidden'); }
    
    async function handleRatingSubmit(e) {
        e.preventDefault();
        const stars = dom.ratingModal.querySelector('#rating-value').value;
        if (stars === '0') { alert(_('Please select a rating.')); return; }
        try {
            const response = await fetch(`/api/users/${otherParticipant.id}/rate`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: JSON.stringify({ stars: parseInt(stars), comment: e.target.comment.value })
            });
            const data = await response.json();
            alert(data.message);
            if(data.success) closeRatingModal();
        } catch(err) { console.error(_("Rating error:"), err); }
    }
    
    function handleStarHover(e) {
        const stars = dom.ratingModal.querySelectorAll('.star-rating .star');
        const hoverValue = e.target.dataset.value;
        stars.forEach(s => { s.textContent = s.dataset.value <= hoverValue ? '★' : '☆'; });
    }
    
    function resetStarHover() {
        const stars = dom.ratingModal.querySelectorAll('.star-rating .star');
        const currentValue = dom.ratingModal.querySelector('#rating-value').value;
        stars.forEach(s => { s.textContent = s.dataset.value <= currentValue ? '★' : '☆'; });
    }
    
    function handleStarClick(e) {
        dom.ratingModal.querySelector('#rating-value').value = e.target.dataset.value;
        resetStarHover();
    }

    // --- Fonctions utilitaires (Gardées de l'original) ---
    function scrollToBottom(instant = false) { // Paramètre 'instant' ajouté
        setTimeout(() => {
            if (dom.messagesDisplay) dom.messagesDisplay.scrollTo({ 
                top: dom.messagesDisplay.scrollHeight, 
                behavior: instant ? 'auto' : 'smooth' // 'auto' pour instantané
            });
        }, 100);
    }

    function checkForInitialChatroom(chatrooms) {
        const urlParams = new URLSearchParams(window.location.search);
        const initialChatroomId = urlParams.get('chatroom_id');
        if (initialChatroomId && chatrooms.some(c => c.id == initialChatroomId)) {
             const roomToJoin = chatrooms.find(c => c.id == initialChatroomId);
             if (roomToJoin) joinChatroom(roomToJoin.id, roomToJoin.other_participant);
             // La ligne 'window.history.replaceState' a été retirée, gérée par le 'popstate'
        }
    }
    
    function handleInputChange() {
        const text = dom.messageInput.value;
        const isRecordingActive = dom.messageInputArea.classList.contains('recording-active');

        if (text.trim() !== '' && !isRecordingActive) {
            switchToSendButton();
        } else if (!isRecordingActive) {
            backToMicButton();
        }

        const textarea = dom.messageInput;
        textarea.style.height = 'auto'; 
        textarea.style.height = `${textarea.scrollHeight}px`;
    }
    function switchToSendButton() {
        dom.micOrSendBtn.classList.remove('mic-mode');
        dom.micOrSendBtn.classList.add('send-mode');
        dom.micOrSendBtn.innerHTML = `<i class="fa-solid fa-paper-plane"></i>`;
    }

    function backToMicButton() {
        dom.micOrSendBtn.classList.remove('send-mode');
        dom.micOrSendBtn.classList.add('mic-mode');
        dom.micOrSendBtn.innerHTML = `<i class="fa-solid fa-microphone"></i>`;
    }
    
    // --- Fonctions d'Upload et Popups (Gardées de l'original) ---
    function handleAttachmentClick(e) {
        const action = e.currentTarget.dataset.action;
        switch (action) {
            case 'gallery': dom.galleryInput.click(); break;
            case 'camera': dom.cameraInput.click(); break;
            case 'document': dom.documentInput.click(); break;
        }
        dom.attachmentPopup.classList.remove('active');
    }
    
    function hideAllPopups() {
        if (attachmentPopupVisible) {
            dom.attachmentPopup.classList.remove('active');
            attachmentPopupVisible = false;
        }
        if (emojiPickerVisible) {
            const picker = document.querySelector('emoji-picker');
            if(picker) picker.classList.remove('visible');
            
            document.body.classList.remove('emoji-picker-active'); // Modifié (original)
            
            const emojiIcon = dom.emojiButton.querySelector('i');
            emojiIcon.classList.remove('fa-keyboard');
            emojiIcon.classList.add('fa-smile');
            emojiPickerVisible = false;
        }
    }


document.addEventListener('click', (e) => {
    // Si le clic n'est pas sur un bouton d'action ou dans un menu...
    if (!e.target.closest('.more-actions-btn') && !e.target.closest('.actions-dropdown')) {
        document.querySelectorAll('.actions-dropdown.visible').forEach(d => d.classList.remove('visible'));
    }
});
    if (dom.messageInput) {
        dom.messageInput.addEventListener('input', handleInputChange);
        dom.messageInput.addEventListener('keyup', handleInputChange);
        // L'écouteur pour 'isTyping' a été retiré par le nouveau code.
    }
    if (dom.micOrSendBtn) {
        dom.micOrSendBtn.addEventListener('click', () => {
            const hasText = dom.messageInput.value.trim().length > 0;
            const isRecordingActive = dom.messageInputArea.classList.contains('recording-active');
            if (isRecordingActive) stopAndSendRecording();
            else if (hasText) sendTextMessage();
            else startRecording();
        });
    }
    // Écouteurs vocaux (Gardés)
    if(dom.cancelVoiceBtn) dom.cancelVoiceBtn.addEventListener('click', cancelRecording);
    if(dom.voiceSendBtn) dom.voiceSendBtn.addEventListener('click', stopAndSendRecording);
    if(dom.cancelReplyBtn) dom.cancelReplyBtn.addEventListener('click', hideReplyPreview);
    if(dom.pauseResumeBtn) dom.pauseResumeBtn.addEventListener('click', pauseOrResumeRecording);
    
    
    if (dom.ratingModal) {
        const closeModalBtn = dom.ratingModal.querySelector('.close-modal-btn');
        if (closeModalBtn) closeModalBtn.addEventListener('click', closeRatingModal);
        dom.ratingModal.addEventListener('click', e => { if (e.target === dom.ratingModal) closeRatingModal(); });
        if (dom.ratingForm) dom.ratingForm.addEventListener('submit', handleRatingSubmit);
        const stars = dom.ratingModal.querySelectorAll('.star-rating .star');
        if (stars) {
            stars.forEach(star => {
                star.addEventListener('mouseover', handleStarHover);
                star.addEventListener('mouseout', resetStarHover);
                star.addEventListener('click', handleStarClick);
            });
        }
    }
    
    // Écouteurs des popups (Gardés)
    if(dom.attachFileButton) {
        dom.attachFileButton.addEventListener('click', (e) => {
            e.stopPropagation(); 
            if (emojiPickerVisible) {
                hideAllPopups();
            }
            attachmentPopupVisible = !dom.attachmentPopup.classList.contains('active');
            dom.attachmentPopup.classList.toggle('active', attachmentPopupVisible);
        });
    }
    if(dom.attachmentPopup) {
        dom.attachmentPopup.querySelectorAll('.attachment-option').forEach(btn => {
            btn.addEventListener('click', handleAttachmentClick);
        });
    }
    
    // NOUVEAU: Écouteurs pour les inputs de fichier (Mis à jour)
    // Ils utilisent tous la nouvelle fonction 'uploadAndSendFiles'
    if(dom.galleryInput) dom.galleryInput.addEventListener('change', (e) => { if(e.target.files.length > 0) uploadAndSendFiles(e.target.files); });
    if(dom.cameraInput) dom.cameraInput.addEventListener('change', (e) => { if(e.target.files.length > 0) uploadAndSendFiles(e.target.files); });
    if(dom.documentInput) dom.documentInput.addEventListener('change', (e) => { if(e.target.files.length > 0) uploadAndSendFiles(e.target.files); });

    // Écouteur Emoji (Gardé)
    if(dom.emojiButton) {
        dom.emojiButton.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (attachmentPopupVisible) hideAllPopups(); 

            let picker = document.querySelector('emoji-picker');
            if (!picker) {
                await import('https://cdn.jsdelivr.net/npm/emoji-picker-element@^1/index.js');
                picker = document.createElement('emoji-picker');
                document.body.appendChild(picker);
                picker.addEventListener('emoji-click', event => {
                    dom.messageInput.value += event.detail.unicode;
                    handleInputChange();
                });
            }

            emojiPickerVisible = !picker.classList.contains('visible');
            document.body.classList.toggle('emoji-picker-active', emojiPickerVisible);
            picker.classList.toggle('visible', emojiPickerVisible);

            const emojiIcon = dom.emojiButton.querySelector('i');
            if (emojiPickerVisible) {
                document.activeElement.blur();
                emojiIcon.classList.remove('fa-smile');
                emojiIcon.classList.add('fa-keyboard');
                scrollToBottom();
            } else {
                emojiIcon.classList.remove('fa-keyboard');
                emojiIcon.classList.add('fa-smile');
                dom.messageInput.focus();
            }
        });
    }
    
    // Écouteurs divers (Gardés)
    document.addEventListener('click', (e) => {
        if (!dom.attachmentPopup.contains(e.target) && !dom.attachFileButton.contains(e.target) &&
            !document.querySelector('emoji-picker')?.contains(e.target) && !dom.emojiButton.contains(e.target)) {
            hideAllPopups();
        }
    });
    
    if (dom.messageInput) {
        dom.messageInput.addEventListener('focus', () => {
            if (emojiPickerVisible) {
                dom.emojiButton.click();
            }
        });
    }
    
    // --- ÉVÉNEMENTS SOCKET.IO (NOUVEAU bloc du nouveau code) ---
    socket.on('connect', () => console.log(_('Socket.IO Connected.')));
    socket.on('message_history', (data) => {
        // 1. On vide le spinner
        dom.messagesDisplay.innerHTML = ''; 
        let lastTimestamp = null;

        // 2. On affiche chaque message de l'historique
        data.messages.forEach(msg => {
            displayMessageBubble(msg, lastTimestamp);
            lastTimestamp = msg.timestamp; // On met à jour pour le prochain tour
        });

        // 3. On défile en bas SANS animation (true = instantané)
        scrollToBottom(true); 
    });
    
// static/js/messages.js

socket.on('new_message', msg => {
    
    // 1. On ignore nos propres messages (correction précédente, inchangée)
    if (String(msg.sender_id) === String(currentUserId)) {
        const chatItem = dom.chatroomsList.querySelector(`.chat-list-item[data-chatroom-id="${msg.chatroom_id}"]`);
        if (chatItem) { 
            updateChatListItem(msg); 
        } else { 
            loadChatrooms(); 
        }
        return; 
    }

    // --- Le code ci-dessous ne s'exécute que pour les messages REÇUS ---
    const chatItem = dom.chatroomsList.querySelector(`.chat-list-item[data-chatroom-id="${msg.chatroom_id}"]`);

    // Si on est DANS la bonne conversation
    if (msg.chatroom_id === currentChatroomId) {
        const lastMessageEl = dom.messagesDisplay.querySelector('.message-wrapper:last-child');
        const lastTimestamp = lastMessageEl ? lastMessageEl.dataset.timestamp : null;
        
        displayMessageBubble(msg, lastTimestamp);
        scrollToBottom();

        // =================================================================
        // --- DÉBUT DE LA CORRECTION (STATUT 1/2) ---
        // Le message est affiché, donc il est 'lu'
        socket.emit('mark_as_read', { message_id: msg.id });
        // =================================================================

    } else {
        // =================================================================
        // --- DÉBUT DE LA CORRECTION (STATUT 2/2) ---
        // On n'est PAS dans la conversation. Le message est 'distribué'.
        socket.emit('message_delivered', { message_id: msg.id });
        // =================================================================
    }

    // Mise à jour de la liste de gauche (logique d'origine, inchangée)
    if (chatItem) {
        updateChatListItem(msg);
    } else {
        loadChatrooms();
    }
});
    
    socket.on('messages_deleted', (data) => {
        data.message_ids.forEach(id => {
            dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${id}']`)?.remove();
        });
        exitSelectionMode();
    });

    socket.on('message_status_updated', (data) => {
    const msgElement = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${data.message_id}'] .message-status`);
    if (msgElement) {
        const icon = msgElement.querySelector('i');
        msgElement.dataset.status = data.status;
        msgElement.classList.toggle('read', data.status === 'read');
        icon.className = (data.status === 'delivered' || data.status === 'read') ? 'fa-solid fa-check-double' : 'fa-solid fa-check';
    }
    // On ne recharge PLUS toute la liste ici pour éviter le saut.
    // La mise à jour se fera au prochain message. C'est un bon compromis.
});

socket.on('bulk_status_update', (data) => {
    data.message_ids.forEach(messageId => {
        const msgElement = dom.messagesDisplay.querySelector(`.message-wrapper[data-message-id='${messageId}'] .message-status`);
        if (msgElement) {
            const icon = msgElement.querySelector('i');
            msgElement.dataset.status = data.status;
            msgElement.classList.add('read');
            icon.className = 'fa-solid fa-check-double';
        }
    });
    // On ne recharge PLUS toute la liste ici.
});

    // Les écouteurs 'typing_status_update' et 'recording_status_update'
    // ont été retirés par le nouveau code.
    
    // Écouteurs de focus/blur clavier (Gardés de l'original)
    if (dom.messageInput) {
        const chatContainerElement = document.querySelector('.chat-container');
        dom.messageInput.addEventListener('focus', () => {
            chatContainerElement.classList.add('keyboard-visible');
            scrollToBottom();
        });

        dom.messageInput.addEventListener('blur', () => {
            chatContainerElement.classList.remove('keyboard-visible');
        });
    }

    // --- INITIALISATION ---
    loadChatrooms();
});