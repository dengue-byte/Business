// Fichier : register.js (version corrigée)

document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('registerForm');
    const passwordInput = document.getElementById('password');
    let locationChoicesInstance = null; 

    // NOUVEAU : Référence au bouton de soumission
    const submitButton = registerForm.querySelector('button[type="submit"]');

    // Initialisation du sélecteur de localisation
    const locationSelect = document.getElementById('location-selector');
    if (locationSelect) {
        window.initAdvancedLocationSelector('location-selector').then(instance => {
            locationChoicesInstance = instance;
            console.log('Location instance initialized:', instance);
        }).catch(err => {
            console.error('Failed to init location selector:', err);
        });
    }

    // --- LOGIQUE DE VALIDATION DU MOT DE PASSE (inchangée) ---
    const rules = {
        length: document.getElementById('length-rule'),
        lower: document.getElementById('lower-rule'),
        upper: document.getElementById('upper-rule'),
        number: document.getElementById('number-rule')
    };
    let passwordIsValid = { length: false, lower: false, upper: false, number: false };

    if (passwordInput) {
        passwordInput.addEventListener('input', () => {
            const pass = passwordInput.value;
            passwordIsValid.length = pass.length >= 6;
            passwordIsValid.lower = /[a-z]/.test(pass);
            passwordIsValid.upper = /[A-Z]/.test(pass);
            passwordIsValid.number = /[0-9]/.test(pass);
            for (const rule in rules) {
                const el = rules[rule];
                if(el) {
                    el.classList.toggle('valid', passwordIsValid[rule]);
                    el.classList.toggle('invalid', !passwordIsValid[rule]);
                }
            }
        });
    }

    // --- LOGIQUE DE SOUMISSION DU FORMULAIRE (corrigée) ---
    if (registerForm) {
        registerForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            // --- DÉBUT DE LA CORRECTION ---
            // On désactive le bouton immédiatement pour éviter les double-clics
            submitButton.disabled = true;
            submitButton.textContent = _('Inscription en cours...'); // Optionnel : informer l'utilisateur
            // --- FIN DE LA CORRECTION ---

            const allValid = Object.values(passwordIsValid).every(val => val === true);
            if (!allValid) {
                displayMessage(_('The password does not meet all the rules.'), 'error');
                // On réactive le bouton en cas d'erreur
                submitButton.disabled = false;
                submitButton.textContent = _('Sign up');
                return;
            }

            const password = registerForm.password.value;
            const confirmPassword = registerForm.confirm_password.value;
            if (password !== confirmPassword) {
                displayMessage(_('The passwords do not match.'), 'error');
                // On réactive le bouton en cas d'erreur
                submitButton.disabled = false;
                submitButton.textContent = _('Sign up');
                return;
            }

            let locationValue = '';
            if (locationChoicesInstance && typeof locationChoicesInstance.getValue === 'function') {
                const val = locationChoicesInstance.getValue();
                if (Array.isArray(val) && val.length > 0) {
                    locationValue = val[0].value || ''; 
                } else if (val && typeof val === 'object' && val.value) {
                    locationValue = val.value; 
                } else {
                    locationValue = val || ''; 
                }
            } else {
                locationValue = locationSelect ? locationSelect.value : '';
            }
            console.log('Sending location:', locationValue); 

            if (!locationValue) {
                displayMessage(_('Please select your department.'), 'error');
                // On réactive le bouton en cas d'erreur
                submitButton.disabled = false;
                submitButton.textContent = _('Sign up');
                return;
            }

            const registrationData = {
                username: registerForm.username.value,
                email: registerForm.email.value,
                password: password,
                location: locationValue
            };

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(registrationData)
                });
                const data = await response.json();

                if (data.success) {
                    displayMessage(data.message, 'success');
                    registerForm.reset();
                    if(locationChoicesInstance) locationChoicesInstance.destroy();
                    // En cas de succès, on laisse tout désactivé
                    registerForm.querySelectorAll('input, select').forEach(el => el.disabled = true);
                    document.querySelector('.form-footer-text').innerHTML = _('Please check your email to activate your account.');
                } else {
                    displayMessage(data.message, 'error');
                    // S'il y a une erreur du serveur, on réactive le bouton
                    submitButton.disabled = false;
                    submitButton.textContent = _('Sign up');
                }
            } catch (error) {
                console.error(_("Registration error:"), error);
                displayMessage(_('A network error occurred.'), 'error');
                // En cas d'erreur réseau, on réactive aussi le bouton
                submitButton.disabled = false;
                submitButton.textContent = _('Sign up');
            }
        });
    }
});