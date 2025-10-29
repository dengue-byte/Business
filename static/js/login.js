// static/js/login.js (Version corrigée pour la connexion par e-mail)

document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');

    if (loginForm) {
        loginForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            // On récupère la valeur du champ e-mail
            const email = loginForm.email.value;
            const password = loginForm.password.value;

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    // On envoie l'e-mail et le mot de passe au serveur
                    body: JSON.stringify({ email: email, password: password })
                });

                const data = await response.json();

                if (data.success) {
                    // Si la connexion réussit, on redirige vers la page d'accueil
                    window.location.href = '/';
                } else {
                    // Sinon, on affiche le message d'erreur
                    displayMessage(data.message, 'error');
                }
            } catch (error) {
                console.error('Login error:', error);
                displayMessage(_('A network error occurred.'), 'error');
            }
        });
    }
});