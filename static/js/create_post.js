document.addEventListener('DOMContentLoaded', () => {
    const createPostForm = document.getElementById('createPostForm');
    const fileInput = document.getElementById('file');
    const previewContainer = document.getElementById('image-preview-container');
    const pillButtons = document.querySelectorAll('.pill-btn');

    let selectedCategory = null;
    let selectedType = null;
    let selectedFiles = [];
    let locationChoicesInstance = null;

    // --- INITIALISATION DU SÉLECTEUR DE LOCALISATION ---
    window.initAdvancedLocationSelector('location-selector', true).then(instance => {
        locationChoicesInstance = instance;
        if (locationChoicesInstance) {
            // Pré-remplir avec la localisation par défaut
            fetch('/api/user/default-location')
                .then(res => res.json())
                .then(data => {
                    if (data.success && data.location) {
                        locationChoicesInstance.setValue([data.location]);
                    }
                }).catch(err => console.warn('Failed to load default location:', err));
        }
    }).catch(err => console.error('Failed to init location selector:', err));

    // --- GESTION DES BOUTONS "PILLULES" (Catégorie & Type) ---
    pillButtons.forEach(button => {
        button.addEventListener('click', () => {
            const group = button.parentElement;
            group.querySelectorAll('.pill-btn').forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            if (button.dataset.category) {
                selectedCategory = button.dataset.category;
            }
            if (button.dataset.type) {
                selectedType = button.dataset.type;
            }
        });
    });

    // --- LOGIQUE DE PRÉVISUALISATION DES IMAGES ---
    fileInput.addEventListener('change', () => {
        handleFiles(fileInput.files);
    });
    
    function handleFiles(files) {
        for (const file of files) {
            if (selectedFiles.length < 5) { // Limite de 5 images
                selectedFiles.push(file);
            }
        }
        renderPreviews();
        updateFileInput();
    }

    function renderPreviews() {
        previewContainer.innerHTML = '';
        selectedFiles.forEach((file, index) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const previewWrapper = document.createElement('div');
                previewWrapper.className = 'image-preview';
                previewWrapper.innerHTML = `
                    <img src="${e.target.result}" alt="${file.name}">
                    <button type="button" class="remove-image-btn" data-index="${index}">&times;</button>
                    ${index === 0 ? `<span class="cover-badge">${_('Cover')}</span>` : ''}
                `;
                previewContainer.appendChild(previewWrapper);
            };
            reader.readAsDataURL(file);
        });
    }

    previewContainer.addEventListener('click', (e) => {
        if (e.target.classList.contains('remove-image-btn')) {
            const indexToRemove = parseInt(e.target.dataset.index, 10);
            selectedFiles.splice(indexToRemove, 1);
            renderPreviews();
            updateFileInput();
        }
    });

    function updateFileInput() {
        const dataTransfer = new DataTransfer();
        selectedFiles.forEach(file => dataTransfer.items.add(file));
        fileInput.files = dataTransfer.files;
    }


    // --- LOGIQUE DE SOUMISSION DU FORMULAIRE ---
    if (createPostForm) {
        createPostForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            
            // Validation
            if (!selectedCategory || !selectedType) {
                displayMessage(_('Please select a category and a type for the ad.'), 'error');
                return;
            }

            const submitButton = createPostForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.innerHTML = `<div class="spinner-small"></div> ${'Publishing...'}`;
            
            const image_paths = [];

            for (const file of selectedFiles) {
                const formData = new FormData();
                formData.append('file', file);
                try {
                    const uploadResponse = await fetch('/api/chat/upload', {
                        method: 'POST',
                        headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
                        body: formData
                    });
                    const uploadData = await uploadResponse.json();
                    if (!uploadData.success) throw new Error(uploadData.message);
                    image_paths.push(uploadData.file_path);
                } catch (error) {
                    displayMessage(error.message, 'error');
                    submitButton.disabled = false;
                    submitButton.innerHTML = `${_('Publish my Ad')} <i class="fa-solid fa-rocket"></i>`;
                    return;
                }
            }
            
            const locationsValue = locationChoicesInstance ? locationChoicesInstance.getValue(true) : [];
            
            const postData = {
                title: createPostForm.title.value,
                description: createPostForm.description.value,
                type: selectedType,
                category: selectedCategory,
                locations: locationsValue,
                image_paths: image_paths
            };

            try {
                const response = await fetch('/api/posts', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': window.getCsrfToken() },
                    body: JSON.stringify(postData)
                });
                const data = await response.json();
                if (data.success) {
                    window.location.href = `/posts/${data.post.id}`;
                } else {
                    throw new Error(data.message);
                }
            } catch (error) {
                displayMessage(error.message || _("Error creating ad."), 'error');
                submitButton.disabled = false;
                submitButton.innerHTML = `${_('Publish my Ad')} <i class="fa-solid fa-rocket"></i>`;
            }
        });
    }
});