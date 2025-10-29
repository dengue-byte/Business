// static/js/geolocation.js (Version AVANCÉE & AUTOMATIQUE - Scoped avec Exposition Fiable)

(function() {
    // Mapping statique : Département (ex. "Mifi") ? Chef-lieu (ex. "Bafoussam")
    const departmentToCapitalMap = {
        "Bamboutos": "Mbouda",
        "Bénoué": "Garoua",
        "Boumba-et-Ngoko": "Yokadouma",
        "Boyo": "Fundong",
        "Bui": "Kumbo",
        "Diamaré": "Maroua",
        "Dja-et-Lobo": "Sangmelima",
        "Djerem": "Tibati",
        "Donga-Mantung": "Nkambé",
        "Fako": "Limbe",
        "Faro": "Poli",
        "Faro-et-Déo": "Tignere",
        "Haute-Sanaga": "Nanga-Eboko",
        "Haut-Nkam": "Bafang",
        "Haut-Nyong": "Abong-Mbang",
        "Hauts-Plateaux": "Baham",
        "Kadey": "Batouri",
        "Koung-Khi": "Badjoun",
        "Koupé-Manengouba": "Bangem",
        "Lebialem": "Menji",
        "Lekié": "Monatele",
        "Logone-et-Chari": "Kousseri",
        "Lom-et-Djerem": "Bertoua",
        "Manyu": "Mamfe",
        "Mayo-Banyo": "Banyo",
        "Mayo-Danay": "Yagoua",
        "Mayo-Kani": "Kaele",
        "Mayo-Louti": "Guider",
        "Mayo-Rey": "Tcholliré",
        "Mayo-Sava": "Mora",
        "Mayo-Tsanaga": "Mokolo",
        "Mbam-et-Inoubou": "Bafia",
        "Mbam-et-Kim": "Ntui",
        "Mbéré": "Meinganga",
        "Mefou-et-Afamba": "Mfou",
        "Mefou-et-Akono": "Ngoumou",
        "Meme": "Kumba",
        "Menchum": "Wum",
        "Menoua": "Dschang",
        "Mezam": "Bamenda",
        "Mfoundi": "Yaoundé",
        "Mifi": "Bafoussam",
        "Momo": "Mbengwi",
        "Moungo": "Nkongsamba",
        "Mvila": "Ebolowa",
        "Ndian": "Mundemba",
        "Ndé": "Bangangte",
        "Ngo-Ketunjia": "Ndop",
        "Nkam": "Yabassi",
        "Noun": "Foumban",
        "Nyong-et-Kéllé": "Eseka",
        "Nyong-et-Mfoumou": "Akonolinga",
        "Nyong-et-So'o": "Mbalmayo",
        "Océan": "Kribi",
        "Sanaga-Maritime": "Edéa",
        "Vallée-du-Ntem": "Ambam",
        "Vina": "Ngaoundéré",
        "Wouri": "Douala"
    };

    async function initAdvancedLocationSelector(selectorId, multiple = false) {
        const selectElement = document.getElementById(selectorId);
        if (!selectElement) {
            console.warn('Select element not found:', selectorId);
            return null;
        }

        // Garde contre réinitialisation multiple
        if (selectElement.hasAttribute('data-choices-initialized')) {
            console.warn('Location selector already initialized');
            return selectElement._choicesInstance || null;
        }
        selectElement.setAttribute('data-choices-initialized', 'true');

        console.log('Initializing location selector... (multiple:', multiple, ')');

        // Config Choices adaptée pour multiple/single
        const choicesConfig = {
            searchEnabled: true,
            itemSelectText: _('Press to select'),
            placeholder: true,
            placeholderValue: _('Detecting location...'),
            shouldSort: false,
            removeItemButton: multiple,  // Bouton X pour multiple
            maxItemCount: multiple ? -1 : 1,  // Illimité pour multiple, 1 pour single
            noChoicesText: _('No locations available'),
            noResultsText: _('No results found')
        };

        const choices = new Choices(selectElement, choicesConfig);
        if (choices && typeof choices.disable === 'function') {
            choices.disable();
        }

        // Stocke l'instance sur l'élément pour récupération future
        selectElement._choicesInstance = choices;

        try {
            // 1. Récupérer la liste complète des départements depuis notre API
            console.log('Fetching locations from API...');
            const response = await fetch('/api/locations', { credentials: 'include' });
            if (!response.ok) {
                throw new Error(`API error: ${response.status} ${response.statusText}`);
            }
            const departmentsData = await response.json();
            if (!departmentsData.success) {
                throw new Error("Could not fetch departments.");
            }

            const allDepartments = departmentsData.locations;
            if (!Array.isArray(allDepartments) || allDepartments.length === 0) {
                throw new Error("No departments data received from API.");
            }
            console.log('API locations loaded:', allDepartments.length, 'departments');

            let finalChoices = allDepartments.map(dep => ({ value: dep, label: dep }));

            // 2. Tenter d'obtenir la position de l'utilisateur (avec checks avancés)
            if ('geolocation' in navigator) {
                console.log('Geolocation API supported');
                
                // Vérifier l'état des permissions avant de lancer
                try {
                    const permissionStatus = await navigator.permissions.query({ name: 'geolocation' });
                    console.log('Geolocation permission state:', permissionStatus.state);
                    
                    if (permissionStatus.state === 'denied') {
                        console.warn('Geolocation denied - skipping detection');
                        handleFallback(choices, finalChoices, _('Select your department... (Geolocation blocked)'));
                        return choices;
                    } else if (permissionStatus.state === 'granted') {
                        console.log('Geolocation already granted - proceeding');
                    }
                    // 'prompt' : On lance getCurrentPosition, qui déclenchera le prompt
                } catch (permError) {
                    console.warn('Permissions API not supported:', permError);
                    // Fallback : Lancer quand même getCurrentPosition
                }

                // Wrapper async pour getCurrentPosition (pour await)
                const getPositionAsync = () => new Promise((resolve, reject) => {
                    navigator.geolocation.getCurrentPosition(resolve, reject, {
                        enableHighAccuracy: true,
                        timeout: 10000,
                        maximumAge: 60000
                    });
                });

                try {
                    console.log('Requesting current position...');
                    const position = await getPositionAsync();
                    console.log('Position obtained:', position.coords.latitude, position.coords.longitude);
                    
                    const { latitude, longitude } = position.coords;
                    
                    // 3. Traduire les coordonnées en nom de département via OpenStreetMap
                    console.log('Geocoding position...');
                    const geoResponse = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}&accept-language=fr`);
                    if (!geoResponse.ok) {
                        console.warn('Geocoding failed:', geoResponse.status);
                        handleFallback(choices, finalChoices, _('Select your department...'));
                        return choices;
                    }
                    const geoData = await geoResponse.json();
                    console.log('Geocoding result:', geoData);
                    
                    if (geoData && geoData.address && geoData.address.county) {
                        let userLocation = geoData.address.county;
                        console.log('Detected department:', userLocation);

                        // Mapping vers chef-lieu si c'est un département
                        let finalUserLocation = userLocation;
                        if (departmentToCapitalMap[userLocation]) {
                            finalUserLocation = departmentToCapitalMap[userLocation];
                            console.log('Mapped department to capital:', userLocation, '?', finalUserLocation);
                        }

                        if (allDepartments.includes(finalUserLocation)) {
                            // Pré-sélection automatique (selected: true pour single, push pour multiple)
                            const autoSelected = { value: finalUserLocation, label: `${finalUserLocation} (${_('Current position')})` };
                            if (!multiple) {
                                autoSelected.selected = true;
                                finalChoices = [autoSelected, ...allDepartments.filter(d => d !== finalUserLocation).map(dep => ({ value: dep, label: dep }))];
                            } else {
                                finalChoices.unshift(autoSelected);  // Ajoute en premier pour multiple
                            }
                            console.log('Auto-selected:', finalUserLocation);
                        } else {
                            console.warn('Mapped location not in list:', finalUserLocation);
                        }
                    } else {
                        console.warn('No county in geocoding response');
                    }
                    
                    updateChoices(choices, finalChoices, _('Select your department...'));
                    return choices;
                    
                } catch (geoError) {
                    console.error('Geolocation error details:', geoError);
                    if (geoError.code === 1) { // PERMISSION_DENIED
                        console.warn('Permission denied - user must allow in browser settings');
                        handleFallback(choices, finalChoices, _('Select your department... (Allow location access?)'));
                    } else {
                        console.warn(`Geolocation error: ${geoError.message}`);
                        handleFallback(choices, finalChoices, _('Select your department...'));
                    }
                    return choices;
                }
            } else {
                console.warn('Geolocation not supported in this browser');
                handleFallback(choices, finalChoices, _('Select your department... (Not supported)'));
                return choices;
            }

        } catch (error) {
            console.error("Failed to initialize location selector:", error);
            if (choices && typeof choices.enable === 'function') {
                choices.enable();
            }
            updateChoices(choices, [], _('Error loading locations'));
            return choices;
        }
    }

    // Fonction helper pour fallback sans geolocation
    function handleFallback(choices, finalChoices, placeholderText) {
        console.log('Using fallback - no geolocation');
        updateChoices(choices, finalChoices, placeholderText);
    }

    // Fonction helper pour mettre à jour Choices et placeholder
    function updateChoices(choices, choicesArray, placeholderText) {
        if (!choices || typeof choices.setChoices !== 'function') {
            console.warn('Choices instance invalid');
            return;
        }
        
        console.log('Updating choices with', choicesArray.length, 'options');
        choices.setChoices(choicesArray, 'value', 'label', true);
        
        if (typeof choices.enable === 'function') {
            choices.enable();
        }
        
        const input = choices.passedElement.element.querySelector('input.choices__input');
        if (input) {
            input.placeholder = placeholderText;
        }
    }

    // Expose la fonction globalement pour appel depuis create_post.js et autres
    window.initAdvancedLocationSelector = initAdvancedLocationSelector;
})();
