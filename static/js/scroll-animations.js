// static/js/scroll-animation.js

document.addEventListener('DOMContentLoaded', () => {
    // Sélectionne tous les éléments que l'on veut animer
    const elementsToAnimate = document.querySelectorAll('.post-card, .form-step, .help-section');

    // L'Intersection Observer est une API moderne et efficace pour détecter la visibilité
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            // Si l'élément entre dans le champ de vision
            if (entry.isIntersecting) {
                // On lui ajoute la classe 'visible' qui déclenchera l'animation CSS
                entry.target.classList.add('visible');
                // On arrête de l'observer pour ne pas répéter l'animation
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1 // L'animation se déclenche quand 10% de l'élément est visible
    });

    // On demande à l'observateur de surveiller chaque élément
    elementsToAnimate.forEach(element => {
        observer.observe(element);
    });
});