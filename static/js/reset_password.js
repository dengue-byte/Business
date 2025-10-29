// static/js/reset_password.js

document.addEventListener('DOMContentLoaded', () => {
    const resetPasswordForm = document.getElementById('resetPasswordForm');
    const passwordInput = document.getElementById('password');
    
    // Logique de validation des règles du mot de passe (similaire à register.js)
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
                if (passwordIsValid[rule]) {
                    rules[rule].classList.remove('invalid');
                    rules[rule].classList.add('valid');
                } else {
                    rules[rule].classList.remove('valid');
                    rules[rule].classList.add('invalid');
                }
            }
        });
    }
    
    // Logique de soumission du formulaire
    if (resetPasswordForm) {
        resetPasswordForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            const allValid = Object.values(passwordIsValid).every(val => val === true);
            if (!allValid) {
                displayMessage(_('The password does not meet all the rules.'), 'error');
                return;
            }

            const password = resetPasswordForm.password.value;
            const confirmPassword = resetPasswordForm.confirm_password.value;
            const token = resetPasswordForm.token.value;

            if (password !== confirmPassword) {
                displayMessage(_('The passwords do not match.'), 'error');
                return;
            }

            try {
                const response = await fetch('/api/reset_password_with_token', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token: token, password: password })
                });
                const data = await response.json();

                if (data.success) {
                    displayMessage(_('Password reset successfully! Redirecting...'), 'success');
                    setTimeout(() => {
                        window.location.href = '/login?message=password_reset_success';
                    }, 2000);
                } else {
                    displayMessage(data.message, 'error');
                }
            } catch (error) {
                displayMessage(_('A network error occurred.'), 'error');
            }
        });
    }
});