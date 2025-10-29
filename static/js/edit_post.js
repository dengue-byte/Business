// DANS static/js/edit_post.js
// REMPLACEZ TOUT LE CONTENU DU FICHIER PAR CE CODE :

document.addEventListener('DOMContentLoaded', async () => {
    const editPostForm = document.getElementById('editPostForm');
    const postId = document.getElementById('postId').value;
    const imagePreviewContainer = document.getElementById('image-preview-container');
    const fileInput = document.getElementById('file');
    
    let existingImagePaths = [];
    // On initialise le sélecteur de localisation en mode multiple
    const locationChoicesInstance = await initAdvancedLocationSelector('location-selector', true);

    // --- Fonctions ---

    function renderImagePreviews() {
        imagePreviewContainer.innerHTML = '';
        existingImagePaths.forEach((path, index) => {
            if (!path) return;
            const preview = document.createElement('div');
            preview.className = 'image-preview';
            preview.innerHTML = `
                <img src="/uploads/${path}" alt="Existing image">
                <button type="button" class="remove-image-btn" data-index="${index}" title="Delete image">&times;</button>
            `;
            imagePreviewContainer.appendChild(preview);
        });
        document.querySelectorAll('.remove-image-btn').forEach(button => {
            button.addEventListener('click', (event) => {
                const indexToRemove = parseInt(event.target.dataset.index, 10);
                existingImagePaths.splice(indexToRemove, 1);
                renderImagePreviews();
            });
        });
    }

    async function loadPostData() {
        try {
            const response = await fetch(`/api/posts/${postId}`);
            const data = await response.json();
            if (data.success) {
                const post = data.post;
                editPostForm.title.value = post.title;
                editPostForm.description.value = post.description;
                editPostForm.type.value = post.type;
                editPostForm.category.value = post.category;
                
                // On pré-remplit le sélecteur de localisation avec les valeurs de l'annonce
                if (locationChoicesInstance && post.locations) {
                    locationChoicesInstance.setValue(post.locations);
                }

                existingImagePaths = post.image_urls.map(url => url.split('/').pop());
                renderImagePreviews();
            } else {
                throw new Error(data.message);
            }
        } catch (error) {
            displayMessage(error.message || _("Unable to load post data."), 'error');
        }
    }

    // --- Logique principale ---

    editPostForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const submitButton = editPostForm.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.textContent = _('Uploading...');

        const newImagePaths = [];

        if (fileInput.files.length > 0) {
            for (const file of fileInput.files) {
                const formData = new FormData();
                formData.append('file', file);
                try {
                    const uploadResponse = await fetch('/api/upload', {
                        method: 'POST',
                        headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
                        body: formData
                    });
                    const uploadData = await uploadResponse.json();
                    if (uploadData.success) {
                        newImagePaths.push(uploadData.file_path);
                    } else { throw new Error(uploadData.message); }
                } catch (error) {
                    displayMessage(error.message || `Upload error for ${file.name}.`, 'error');
                    submitButton.disabled = false;
                    submitButton.textContent = _("Update the ad");
                    return;
                }
            }
        }

        submitButton.textContent = _('Updating...');
        
        // On récupère le tableau des localisations mises à jour
        const locationsValue = locationChoicesInstance ? locationChoicesInstance.getValue(true) : [];

        const updatedData = {
            title: editPostForm.title.value,
            description: editPostForm.description.value,
            type: editPostForm.type.value,
            category: editPostForm.category.value,
            locations: locationsValue, // On envoie le nouveau tableau de localisations
            image_paths: [...existingImagePaths, ...newImagePaths]
        };

        try {
            const response = await fetch(`/api/posts/${postId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: JSON.stringify(updatedData)
            });
            const result = await response.json();
            if (result.success) {
                displayMessage(_('Ad updated successfully!'), 'success');
                setTimeout(() => { window.location.href = '/my_posts'; }, 1500);
            } else {
                throw new Error(result.message);
            }
        } catch (error) {
            displayMessage(error.message || _('Error updating.'), 'error');
            submitButton.disabled = false;
            submitButton.textContent = _("Update the ad");
        }
    });

    loadPostData();
});