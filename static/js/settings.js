// Dans static/js/settings.js (Version finale et unifiée)

document.addEventListener('DOMContentLoaded', () => {

    // --- Fonctions génériques pour gérer les modales ---
    const openModal = (modal) => modal.classList.remove('hidden');
    const closeModal = (modal) => modal.classList.add('hidden');

    // --- GESTION DES MODALES ---
    const profileModal = document.getElementById('profile-modal');
    const passwordModal = document.getElementById('password-modal');
    const deleteModal = document.getElementById('delete-confirm-modal');

    // Boutons d'ouverture
    const openProfileBtn = document.getElementById('open-profile-modal');
    if (openProfileBtn) openProfileBtn.addEventListener('click', () => openModal(profileModal));

    const openPasswordBtn = document.getElementById('open-password-modal');
    if (openPasswordBtn) openPasswordBtn.addEventListener('click', () => openModal(passwordModal));

    const openDeleteBtn = document.getElementById('open-delete-modal');
    if (openDeleteBtn) openDeleteBtn.addEventListener('click', () => {
        if (confirm(_("Attention: This action is irreversible. Do you really want to continue?"))) {
            openModal(deleteModal);
        }
    });

    // Boutons de fermeture
    document.querySelectorAll('.modal-overlay').forEach(modal => {
        const closeBtn = modal.querySelector('.close-modal-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => closeModal(modal));
        }
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal(modal);
        });
    });
    const cancelDeleteBtn = document.querySelector('.cancel-delete-btn');
    if (cancelDeleteBtn) cancelDeleteBtn.addEventListener('click', () => closeModal(deleteModal));


    // --- GESTION DU CHANGEMENT DE LANGUE ---
    const languageSwitcher = document.querySelector('#language-switcher');
    if (languageSwitcher) {
        languageSwitcher.addEventListener('change', async (e) => {
            const lang = e.target.value;
            try {
                const response = await fetch('/api/user/change_language', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify({ language: lang })
                });
                const data = await response.json();
                if (response.ok) {
                    location.reload(true);
                } else {
                    displayMessage(data.message, 'error', 'settings-message-container');
                }
            } catch (error) {
                displayMessage(_('Network error.'), 'error', 'settings-message-container');
            }
        });
    }

    // --- GESTION DU FORMULAIRE DE PROFIL ---
    const profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;

            try {
                const response = await fetch('/api/user/profile', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify({ username, email })
                });
                const data = await response.json();
                displayMessage(data.message, response.ok ? 'success' : 'error', 'settings-message-container');
                if (response.ok) closeModal(profileModal);
            } catch (error) {
                displayMessage(_('A network error occurred.'), 'error', 'settings-message-container');
            }
        });
    }

    // --- GESTION DE LA PHOTO DE PROFIL ---
    const photoUploadContainer = document.getElementById('photo-upload-container');
    if (photoUploadContainer) {
        const photoFile = document.getElementById('photo-file');
        const previewWrapper = document.getElementById('photo-preview-wrapper');
        const buttonsWrapper = document.getElementById('photo-buttons-wrapper');
        const usernameInput = document.getElementById('username');

        const handleUpload = async (file) => {
            const formData = new FormData();
            formData.append('file', file);
            try {
                const response = await fetch('/api/user/profile-photo', {
                    method: 'POST',
                    body: formData,
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() }
                });
                const data = await response.json();
                if (response.ok && data.photo_url) {
                    previewWrapper.innerHTML = `<img id="current-photo" src="${data.photo_url}?t=${new Date().getTime()}" alt="Profile photo" class="current-photo-preview">`;
                    buttonsWrapper.innerHTML = `
                        <button type="button" id="edit-photo-btn" class="photo-btn primary">Edit</button>
                        <button type="button" id="delete-photo-btn" class="photo-btn danger">Delete</button>`;
                    attachButtonListeners();
                    displayMessage(_('Photo updated!'), 'success', 'settings-message-container');
                } else {
                    displayMessage(data.message || _("Upload error."), 'error', 'settings-message-container');
                }
            } catch (error) {
                displayMessage(_('Network error.'), 'error', 'settings-message-container');
            }
        };

        const handleDelete = async () => {
            if (!confirm(_('Do you really want to delete your profile photo?'))) return;
            try {
                const response = await fetch('/api/user/profile-photo', {
                    method: 'DELETE',
                    headers: { 'X-CSRF-TOKEN': window.getCsrfToken() }
                });
                if (response.ok) {
                    const username = usernameInput.value;
                    previewWrapper.innerHTML = `
                        <div id="empty-avatar-placeholder" class="empty-avatar" style="cursor: pointer;">
                            <span>${username[0].toUpperCase()}</span>
                            <i class="fa-solid fa-camera" style="color: rgba(255,255,255,0.8); font-size: 1.2rem; margin-top: 0.5rem;"></i>
                            <p style="font-size: 0.8rem; margin-top: 0.2rem;">Add a photo</p>
                        </div>`;
                    buttonsWrapper.innerHTML = `<button type="button" id="add-photo-btn" class="photo-btn primary">Add a photo</button>`;
                    attachButtonListeners();
                    displayMessage(_('Photo deleted.'), 'success', 'settings-message-container');
                } else {
                    displayMessage(_('Error deleting.'), 'error', 'settings-message-container');
                }
            } catch (error) {
                displayMessage(_('Network error.'), 'error', 'settings-message-container');
            }
        };

        const attachButtonListeners = () => {
            const addBtn = document.getElementById('add-photo-btn');
            const editBtn = document.getElementById('edit-photo-btn');
            const deleteBtn = document.getElementById('delete-photo-btn');
            const placeholder = document.getElementById('empty-avatar-placeholder');
            if (addBtn) addBtn.addEventListener('click', () => photoFile.click());
            if (editBtn) editBtn.addEventListener('click', () => photoFile.click());
            if (deleteBtn) deleteBtn.addEventListener('click', handleDelete);
            if (placeholder) placeholder.addEventListener('click', () => photoFile.click());
        };

        attachButtonListeners();
        photoFile.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) handleUpload(file);
        });
    }

    // --- GESTION DU CHANGEMENT DE MOT DE PASSE ---
    const passwordForm = document.getElementById('password-form');
    if (passwordForm) {
        passwordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const current_password = document.getElementById('current-password').value;
            const new_password = document.getElementById('new-password').value;
            try {
                const response = await fetch('/api/user/change_password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify({ current_password, new_password })
                });
                const data = await response.json();
                displayMessage(data.message, response.ok ? 'success' : 'error', 'settings-message-container');
                if (response.ok) {
                    passwordForm.reset();
                    closeModal(passwordModal);
                }
            } catch (error) {
                displayMessage(_('A network error occurred.'), 'error', 'settings-message-container');
            }
        });
    }

    // --- GESTION DE LA DÉCONNEXION ---
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            if (confirm(_("Do you really want to log out?"))) {
                window.logout();
            }
        });
    }

    // --- GESTION DE LA SUPPRESSION DE COMPTE ---
    const deleteConfirmForm = document.getElementById('delete-confirm-form');
    if (deleteConfirmForm) {
        deleteConfirmForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('delete-password').value;
            try {
                const response = await fetch('/api/user/delete', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify({ password })
                });
                const data = await response.json();
                if (response.ok) {
                    alert(data.message);
                    window.location.href = '/';
                } else {
                    alert(_("Error: ") + data.message);
                }
            } catch (error) {
                alert(_('A network error occurred.'));
            }
        });
    }
});