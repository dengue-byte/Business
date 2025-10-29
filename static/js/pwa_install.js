let deferredPrompt;

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  // Affiche un bouton install si désiré
  const installBtn = document.getElementById('install-btn');  // Ajoute <button id="install-btn">Installer App</button> dans base.html si besoin
  if (installBtn) installBtn.style.display = 'block';
});

if (installBtn) {
  installBtn.addEventListener('click', async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      console.log(`User response to install: ${outcome}`);
      deferredPrompt = null;
    }
  });
}