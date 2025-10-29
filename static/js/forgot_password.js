// static/js/forgot_password.js

document.addEventListener('DOMContentLoaded', () => {
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');

    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const email = forgotPasswordForm.email.value;
            const submitButton = forgotPasswordForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.textContent = _('Sending...');

            try {
                const response = await fetch('/api/request_password_reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email })
                });

                const data = await response.json();
                
                // --- MODIFIÉ ---
                // On affiche un message plus patient et informatif
                if (data.success) {
                    displayMessage(_("Si un compte existe, un email a été envoyé. Cela peut prendre 1 à 2 minutes."), 'success');
                } else {
                    displayMessage(data.message, 'error');
                }

            } catch (error) {
                displayMessage(_('A network error occurred.'), 'error');
            } finally {
                // On ne réactive pas le bouton immédiatement pour éviter le spam
                setTimeout(() => {
                    submitButton.disabled = false;
                    submitButton.textContent = _('Send the reset link');
                }, 30000); // 30 secondes d'attente
            }
        });
    }
});