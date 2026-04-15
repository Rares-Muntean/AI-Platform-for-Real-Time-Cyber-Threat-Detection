import numpy as np
from sklearn.cluster import KMeans
import joblib
import os


class SignatureClusterAI:
    def __init__(self):
        # 1. Admin Noise (apt update, scp)
        # 2. Scans (Port/RST errors)
        # 3. Floods (Static repeating errors)
        self.model = KMeans(n_clusters=3, random_state=42, n_init=10)
        self.is_trained = False

        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.model_path = os.path.join(current_dir, '..', 'models', 'cluster_model.pkl')

    def train_on_signatures(self, signatures):
        print(f"Training Clustering AI on {len(signatures)} anomaly signatures...")
        self.model.fit(signatures)
        self.is_trained = True
        joblib.dump(self.model, self.model_path)
        print("Clustering AI Trained and Saved!")

    def load(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            self.is_trained = True

    def categorize_threat(self, error_signature):
        if not self.is_trained:
            return "UNKNOWN_CLUSTER"

        cluster_id = self.model.predict([error_signature])[0]

        return f"Cluster-{cluster_id}"