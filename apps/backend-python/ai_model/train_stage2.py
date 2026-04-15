import numpy as np
import os
from cluster_ai import SignatureClusterAI

current_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(current_dir, '..', 'datasets', 'anomaly_signatures.csv')

print(f"Loading signatures from {csv_path}...")
try:
    # Automatically load all signatures you collected
    training_signatures = np.loadtxt(csv_path, delimiter=",")

    print(f"Successfully loaded {len(training_signatures)} anomaly signatures.")

    ai = SignatureClusterAI()
    ai.train_on_signatures(training_signatures)

except FileNotFoundError:
    print("No signatures found! Run the sniffer and trigger some anomalies first.")