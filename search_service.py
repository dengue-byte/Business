import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
import os
import pickle
import re

# (MODIFICATION) On passe à un modèle d'IA beaucoup plus puissant
MODEL_NAME = 'all-MiniLM-L6-v2'
INDEX_FILE = 'faiss_index.bin'
MAP_FILE = 'faiss_map.pkl'

# Seuil de similarité ajusté pour le nouveau modèle
SIMILARITY_THRESHOLD = 0.45

def _preprocess_text(text):
    text = text.lower()
    text = re.sub(r'[^\w\s]', ' ', text) # Remplace la ponctuation par des espaces
    text = re.sub(r'\s+', ' ', text).strip() # Supprime les espaces multiples
    return text

class SearchService:
    def __init__(self):
        print(f"Chargement du modèle de recherche sémantique: {MODEL_NAME}...")
        self.model = SentenceTransformer(MODEL_NAME)
        self.index = None
        self.id_map = []
        self.load_index()
        print("Modèle et index chargés.")

    def load_index(self):
        if os.path.exists(INDEX_FILE) and os.path.exists(MAP_FILE):
            print(f"Chargement de l'index depuis le fichier '{INDEX_FILE}'...")
            self.index = faiss.read_index(INDEX_FILE)
            with open(MAP_FILE, 'rb') as f:
                self.id_map = pickle.load(f)
        else:
            print("Aucun index trouvé. Il devra être créé.")

    def build_index(self, posts):
        print("Création de l'index sémantique à partir des annonces...")
        if not posts:
            print("Aucune annonce à indexer.")
            return

        texts = [_preprocess_text(f"{post.title}. {post.description}") for post in posts]
        
        embeddings = self.model.encode(texts, convert_to_tensor=True, show_progress_bar=True)
        embeddings_np = embeddings.cpu().numpy().astype('float32')
        faiss.normalize_L2(embeddings_np)
        
        embedding_dim = embeddings_np.shape[1]
        self.index = faiss.IndexIDMap(faiss.IndexFlatIP(embedding_dim))
        
        self.id_map = [post.id for post in posts]
        ids_array = np.array(self.id_map, dtype='int64')

        self.index.add_with_ids(embeddings_np, ids_array)
        
        faiss.write_index(self.index, INDEX_FILE)
        with open(MAP_FILE, 'wb') as f:
            pickle.dump(self.id_map, f)
        
        print(f"Index créé et sauvegardé avec {len(posts)} annonces.")

    def semantic_search(self, query, k=20):
        if self.index is None or self.index.ntotal == 0:
            return []

        processed_query = _preprocess_text(query)
        
        query_embedding = self.model.encode([processed_query], convert_to_tensor=True)
        query_embedding_np = query_embedding.cpu().numpy().astype('float32')
        faiss.normalize_L2(query_embedding_np)

        # On recherche un peu plus de résultats pour avoir de la marge avec le seuil
        search_k = min(k * 2, self.index.ntotal)
        distances, ids = self.index.search(query_embedding_np, k=search_k)

        relevant_ids = [int(id_) for id_, dist in zip(ids[0], distances[0]) if dist > SIMILARITY_THRESHOLD]
        
        # On ne retourne que les 'k' meilleurs résultats
        return relevant_ids[:k]

search_service = SearchService()
