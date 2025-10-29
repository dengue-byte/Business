document.addEventListener('DOMContentLoaded', () => {
    const uploadArea = document.getElementById('upload-area');
    const photoInput = document.getElementById('photo-input');
    const previewContainer = document.getElementById('preview-container');
    const previewImg = document.getElementById('preview-img');
    const uploadBtn = document.getElementById('upload-btn');
    const ignoreBtn = document.getElementById('ignore-btn');
    const cancelBtn = document.getElementById('cancel-btn');

    // Drag & drop
    uploadArea.addEventListener('dragover', (e) => e.preventDefault());
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) handleFile(file);
    });
    uploadArea.addEventListener('click', () => photoInput.click());
    photoInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) handleFile(file);
    });

    function handleFile(file) {
        const reader = new FileReader();
        reader.onload = (e) => {
            previewImg.src = e.target.result;
            previewContainer.classList.remove('hidden');
        };
        reader.readAsDataURL(file);
    }

    uploadBtn.addEventListener('click', async () => {
        const formData = new FormData();
        formData.append('file', photoInput.files[0]);
        try {
            const response = await fetch('/api/user/profile-photo', {
                method: 'POST',
                headers: { 'X-CSRF-TOKEN': window.getCsrfToken() },
                body: formData
            });
            const data = await response.json();
            if (data.success) {
                displayMessage(_('Photo saved!'), 'success');
                setTimeout(() => window.location.href = '/', 1500);
            } else {
                displayMessage(data.message, 'error');
            }
        } catch (error) {
            displayMessage(_('Upload error'), 'error');
        }
    });

    ignoreBtn.addEventListener('click', () => window.location.href = '/');
    cancelBtn.addEventListener('click', () => {
        previewContainer.classList.add('hidden');
        photoInput.value = '';
    });
});