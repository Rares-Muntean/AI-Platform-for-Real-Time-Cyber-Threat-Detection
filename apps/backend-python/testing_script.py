import pandas as pd
import numpy as np
import torch
from model_logic import CyberAI

# 1. Load the Master AI
brain = CyberAI(input_dim=10)
brain.load("models/model.pth", "models/scaler.pkl")
print(f"AI Loaded. Threshold: {brain.threshold:.6f}")

input_file = "E:/NF-UQ-NIDS-v2.csv/NF-UQ-NIDS-v2.csv"

# The same columns we used for training
selected_cols = [
    'L4_DST_PORT', 'LONGEST_FLOW_PKT', 'FLOW_DURATION_MILLISECONDS',
    'TCP_FLAGS', 'MIN_TTL', 'TCP_WIN_MAX_OUT',
    'IN_BYTES', 'Label', 'Attack'  # Added 'Attack' to see the name
]

print("\nScanning 13GB file for real attacks to test...")

# We will collect a few examples of different attacks
attack_samples = []

# Read in chunks to find attacks
for chunk in pd.read_csv(input_file, usecols=selected_cols, chunksize=200000):
    # Filter for Attacks (Label 1)
    attack_chunk = chunk[chunk['Label'] == 1].copy()

    if not attack_chunk.empty:
        # Process them EXACTLY like training
        flags = attack_chunk['TCP_FLAGS'].astype(int)
        attack_chunk['is_syn'] = (flags & 2).astype(bool).astype(int)
        attack_chunk['is_ack'] = (flags & 16).astype(bool).astype(int)
        attack_chunk['is_rst'] = (flags & 4).astype(bool).astype(int)
        attack_chunk['is_fin'] = (flags & 1).astype(bool).astype(int)

        attack_chunk['dest_port'] = np.log1p(attack_chunk['L4_DST_PORT'])
        attack_chunk['packet_size'] = np.log1p(attack_chunk['LONGEST_FLOW_PKT'])
        attack_chunk['time_delta'] = np.log1p(attack_chunk['FLOW_DURATION_MILLISECONDS'] / 1000.0)
        attack_chunk['ttl'] = attack_chunk['MIN_TTL']
        attack_chunk['tcp_window'] = np.log1p(attack_chunk['TCP_WIN_MAX_OUT'])
        attack_chunk['payload_len'] = np.log1p(attack_chunk['IN_BYTES'])

        final_cols = ['dest_port', 'packet_size', 'time_delta', 'is_syn', 'is_ack', 'is_rst', 'is_fin', 'ttl',
                      'tcp_window', 'payload_len', 'Attack']

        attack_samples.append(attack_chunk[final_cols])

        # Stop once we have 5000 samples to test
        if sum(len(x) for x in attack_samples) >= 5000:
            break

# Combine all found attacks
df_attacks = pd.concat(attack_samples)

print(f"{'Attack Type':<20} | {'Score':<10} | {'Status'}")
print("-" * 50)

# Test the first 20 found attacks
for i in range(20):
    row_data = df_attacks.iloc[i]
    attack_name = row_data['Attack']

    # Remove 'Attack' label before feeding to AI
    features = row_data.drop('Attack').values.reshape(1, -1)

    score = brain.get_anomaly_score(features)
    status = "🔴 DETECTED" if score > brain.threshold else "🟢 MISSED"

    print(f"{attack_name:<20} | {score:.6f} | {status}")