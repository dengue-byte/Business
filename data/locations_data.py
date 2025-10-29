# << data/locations_data.py >>

def get_locations_data():
    return {
        "Adamaoua": {
            "capital": "Ngaoundéré",
            "departments": {
                "Djérem": {"capital": "Tibati", "arrondissements": ["Nganha", "Tibati"]},
                "Faro-et-Déo": {"capital": "Tignère", "arrondissements": ["Galim-Tignère", "Mayo-Baléo", "Tignère"]},
                "Mayo-Banyo": {"capital": "Banyo", "arrondissements": ["Banyo", "Bankim", "Mayo-Darlé"]},
                "Mbéré": {"capital": "Meiganga", "arrondissements": ["Dir", "Djohong", "Meiganga", "Ngaoui"]},
                "Vina": {"capital": "Ngaoundéré", "arrondissements": ["Belel", "Mbé", "Ngaoundéré I", "Ngaoundéré II", "Ngaoundéré III", "Nyambaka", "Martap"]}
            }
        },
        "Centre": {
            "capital": "Yaoundé",
            "departments": {
                "Haute-Sanaga": {"capital": "Nanga-Eboko", "arrondissements": ["Bibey", "Lembe-Yezoum", "Mbandjock", "Minta", "Nanga-Eboko", "Nkoteng", "Nsang"]},
                "Lekié": {"capital": "Monatélé", "arrondissements": ["Batchenga", "Ebebda", "Elig-Mfomo", "Evodoula", "Monatélé", "Obala", "Okola", "Sa'a", "Soaa"]},
                "Mbam-et-Inoubou": {"capital": "Bafia", "arrondissements": ["Bafia", "Bokito", "Deuk", "Kiiki", "Kon-Yambetta", "Makénéné", "Ndikiniméki", "Nitoukou", "Ombessa"]},
                "Mbam-et-Kim": {"capital": "Ntui", "arrondissements": ["Mbangassina", "Ngambè-Tikar", "Ngoro", "Ntui", "Yoko"]},
                "Méfou-et-Afamba": {"capital": "Mfou", "arrondissements": ["Awaé", "Edzendouan", "Esse", "Mfou", "Nkolafamba", "Olanguina", "Soa"]},
                "Méfou-et-Akono": {"capital": "Ngoumou", "arrondissements": ["Akono", "Bikok", "Mbankomo", "Ngoumou"]},
                "Mfoundi": {"capital": "Yaoundé", "arrondissements": ["Yaoundé I", "Yaoundé II", "Yaoundé III", "Yaoundé IV", "Yaoundé V", "Yaoundé VI", "Yaoundé VII"]},
                "Nyong-et-Kéllé": {"capital": "Éséka", "arrondissements": ["Biyouha", "Bondjock", "Bot-Makak", "Dibang", "Éséka", "Makak", "Matomb", "Messondo", "Ngog-Mapubi", "Ngui-Bassal"]},
                "Nyong-et-Mfoumou": {"capital": "Akonolinga", "arrondissements": ["Akonolinga", "Ayos", "Endom", "Kobdombo", "Mengang"]},
                "Nyong-et-So'o": {"capital": "Mbalmayo", "arrondissements": ["Akoeman", "Dzeng", "Mbalmayo", "Mengueme", "Ngomedzap", "Nkolmetet"]}
            }
        },
        "Est": {
            "capital": "Bertoua",
            "departments": {
                "Boumba-et-Ngoko": {"capital": "Yokadouma", "arrondissements": ["Gari-Gombo", "Moloundou", "Salapoumbé", "Yokadouma"]},
                "Haut-Nyong": {"capital": "Abong-Mbang", "arrondissements": ["Abong-Mbang", "Angossas", "Atok", "Dimako", "Doumaintang", "Doumé", "Lomié", "Mboma", "Messamena", "Messok", "Mindourou", "Ngoyla", "Somalomo", "Zouetel"]},
                "Kadey": {"capital": "Batouri", "arrondissements": ["Batouri", "Bombé", "Kette", "Mbang", "Ndelele", "Nguelebok", "Ouli"]},
                "Lom-et-Djérem": {"capital": "Bertoua", "arrondissements": ["Belabo", "Bertoua I", "Bertoua II", "Betare-Oya", "Diang", "Garoua-Boulaï", "Mandjou", "Ngaoundal"]}
            }
        },
        "Extrême-Nord": {
            "capital": "Maroua",
            "departments": {
                "Diamaré": {"capital": "Maroua", "arrondissements": ["Bogo", "Dargala", "Gawaza", "Maroua I", "Maroua II", "Maroua III", "Meri", "Ndoukoula", "Petté"]},
                "Logone-et-Chari": {"capital": "Kousséri", "arrondissements": ["Blangoua", "Darak", "Fotokol", "Goulfey", "Hile-Alifa", "Kousséri", "Logone-Birni", "Makary", "Waza", "Zina"]},
                "Mayo-Danay": {"capital": "Yagoua", "arrondissements": ["Datcheka", "Gobo", "Guéré", "NGuidiguis", "Kalfou", "Kar-Hay", "Maga", "Tchati-Bali", "Vélé", "Wina", "Yagoua"]},
                "Mayo-Kani": {"capital": "Kaélé", "arrondissements": ["Dziguilao", "Guidiguis", "Kaélé", "Mindif", "Moulvoudaye", "Moutourwa", "Porhi"]},
                "Mayo-Sava": {"capital": "Mora", "arrondissements": ["Kolofata", "Mora", "Tokombéré"]},
                "Mayo-Tsanaga": {"capital": "Mokolo", "arrondissements": ["Bourrha", "Hina", "Koza", "Mogodé", "Mokolo", "Roua", "Soulédé-Roua"]}
            }
        },
        "Littoral": {
            "capital": "Douala",
            "departments": {
                "Moungo": {"capital": "Nkongsamba", "arrondissements": ["Baré-Bakem", "Bonaléa", "Dibombari", "Ebone", "Loum", "Manjo", "Mbanga", "Melong", "Mombo", "Nkongsamba I", "Nkongsamba II", "Nkongsamba III", "Penja"]},
                "Nkam": {"capital": "Yabassi", "arrondissements": ["Ndobian", "Nkondjock", "Yabassi", "Yingui"]},
                "Sanaga-Maritime": {"capital": "Édéa", "arrondissements": ["Dizangué", "Édéa I", "Édéa II", "Massock-Songloulou", "Mouanko", "Ndom", "Ngambe", "Ngwei", "Nyanon", "Pouma"]},
                "Wouri": {"capital": "Douala", "arrondissements": ["Douala I", "Douala II", "Douala III", "Douala IV", "Douala V", "Douala VI"]}
            }
        },
        "Nord": {
            "capital": "Garoua",
            "departments": {
                "Bénoué": {"capital": "Garoua", "arrondissements": ["Barndaké", "Baschéo", "Bibemi", "Dembo", "Garoua I", "Garoua II", "Garoua III", "Gashiga", "Lagdo", "Mayo-Hourna", "Pitoa", "Touroua"]},
                "Faro": {"capital": "Poli", "arrondissements": ["Beka", "Poli"]},
                "Mayo-Louti": {"capital": "Guider", "arrondissements": ["Figuil", "Guider", "Mayo-Oulo"]},
                "Mayo-Rey": {"capital": "Tcholliré", "arrondissements": ["Mandama", "Madingring", "Rey-Bouba", "Tcholliré", "Touboro"]}
            }
        },
        "Nord-Ouest": {
            "capital": "Bamenda",
            "departments": {
                "Boyo": {"capital": "Fundong", "arrondissements": ["Belo", "Fundong", "Njinikom", "Funfuka"]},
                "Bui": {"capital": "Kumbo", "arrondissements": ["Elak-Oku", "Jakiri", "Kumbo", "Mbiame", "Nkor", "Noni"]},
                "Donga-Mantung": {"capital": "Nkambé", "arrondissements": ["Ako", "Misaje", "Ndu", "Nkambé", "Nwa"]},
                "Menchum": {"capital": "Wum", "arrondissements": ["Benakuma", "Furu-Awa", "Wum", "Zhoa"]},
                "Mezam": {"capital": "Bamenda", "arrondissements": ["Bafut", "Bali", "Bamenda I", "Bamenda II", "Bamenda III", "Santa", "Tubah"]},
                "Momo": {"capital": "Mbengwi", "arrondissements": ["Andek", "Batibo", "Mbengwi", "Njikwa", "Widikum-Boffe"]},
                "Ngo-Ketunjia": {"capital": "Ndop", "arrondissements": ["Babessi", "Balikumbat", "Ndop"]}
            }
        },
        "Ouest": {
            "capital": "Bafoussam",
            "departments": {
                "Bamboutos": {"capital": "Mbouda", "arrondissements": ["Babadjou", "Batcham", "Galim", "Mbouda"]},
                "Haut-Nkam": {"capital": "Bafang", "arrondissements": ["Bafang", "Bakou", "Bana", "Bandja", "Bankā", "Kekem"]},
                "Hauts-Plateaux": {"capital": "Baham", "arrondissements": ["Baham", "Bamendjou", "Bangou", "Batié"]},
                "Koung-Khi": {"capital": "Bandjoun", "arrondissements": ["Bandjoun", "Bayangam", "Demding"]},
                "Ménoua": {"capital": "Dschang", "arrondissements": ["Dschang", "Fokoué", "Fongo-Tongo", "Nkong-Zem", "Penka-Michel", "Santchou"]},
                "Mifi": {"capital": "Bafoussam", "arrondissements": ["Bafoussam I", "Bafoussam II", "Bafoussam III", "Baleng", "Lafé-Baleng"]},
                "Ndé": {"capital": "Bangangté", "arrondissements": ["Bangangté", "Bangoulap", "Bassamba", "Bazou", "Tonga"]},
                "Noun": {"capital": "Foumban", "arrondissements": ["Bangourain", "Foumban", "Foumbot", "Kouoptamo", "Koutaba", "Magba", "Malentouen", "Massangam", "Njimom"]}
            }
        },
        "Sud": {
            "capital": "Ebolowa",
            "departments": {
                "Dja-et-Lobo": {"capital": "Sangmélima", "arrondissements": ["Bengbis", "Djoum", "Meyomessala", "Meyomessi", "Mintom", "Oveng", "Sangmélima", "Zoétélé"]},
                "Mvila": {"capital": "Ebolowa", "arrondissements": ["Biwong-Bane", "Biwong-Bulu", "Ebolowa I", "Ebolowa II", "Efoulan", "Mengong", "Mvangan", "Ngoulemakong"]},
                "Océan": {"capital": "Kribi", "arrondissements": ["Akom II", "Bipindi", "Campo", "Kribi I", "Kribi II", "Lokoundjé", "Lolodorf", "Mvengue", "Niete"]},
                "Vallée-du-Ntem": {"capital": "Ambam", "arrondissements": ["Ambam", "Kye-Ossi", "Ma'an", "Olamze"]}
            }
        },
        "Sud-Ouest": {
            "capital": "Buéa",
            "departments": {
                "Fako": {"capital": "Limbé", "arrondissements": ["Buéa", "Limbé I", "Limbé II", "Limbé III", "Muyuka", "Tiko", "West Coast"]},
                "Koupé-Manengouba": {"capital": "Bangem", "arrondissements": ["Bangem", "Nguti", "Tombel"]},
                "Lebialem": {"capital": "Menji", "arrondissements": ["Alou", "Menji", "Wabane"]},
                "Manyu": {"capital": "Mamfé", "arrondissements": ["Akwaya", "Eyumodjock", "Mamfé", "Upper Bayang"]},
                "Meme": {"capital": "Kumba", "arrondissements": ["Konye", "Kumba I", "Kumba II", "Kumba III", "Mbonge"]},
                "Ndian": {"capital": "Mundemba", "arrondissements": ["Bamusso", "Ekondo-Titi", "Idabato", "Isanguele", "Kombo-Abedimo", "Kombo-Idinti", "Mundemba", "Toko"]}
            }
        }
    }