import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
import random
from sklearn.preprocessing import RobustScaler
from torch.utils.data import DataLoader, TensorDataset

from ai_model.cyber_ai import CyberAI

EPOCHS = 30  # Increased slightly since dataset is smaller
BATCH_SIZE = 1024  # Smaller batch size for smaller dataset
SEED = 42


def set_seeds(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


set_seeds(SEED)

# 1. ONLY LOAD THE LOCAL CALIBRATION DATA
df_local = pd.read_csv("../datasets/local_calibration.csv")
df_local.dropna(inplace=True)

heavy_traffic = df_local[df_local['dest_port'] >= 4.0]
light_traffic = df_local[df_local['dest_port'] < 4.0]

# Multiply heavy traffic MORE so the AI learns it properly
heavy_multiplied = pd.concat([heavy_traffic] * 200, ignore_index=True)
light_multiplied = pd.concat([light_traffic] * 50, ignore_index=True)

# Combine them back together
local_multiplied = pd.concat([heavy_multiplied, light_multiplied], ignore_index=True)

# 2. Multiply to create enough rows for deep learning
# local_multiplied = pd.concat([df_local] * 50, ignore_index=True)

# --- START OF DATA AUGMENTATION (Network Noise) ---
# This prevents the AI from memorizing exact packet sizes
size_cols = ['fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'pkt_len_mean']
for col in size_cols:
    noise = np.random.uniform(-0.15, 0.15, size=len(local_multiplied))
    local_multiplied[col] = local_multiplied[col] * (1 + noise)

# This protects you from mobile hotspot lag (up to 200% variance)
timing_noise = np.random.uniform(-0.10, 2.00, size=len(local_multiplied))
local_multiplied['flow_iat_mean'] = local_multiplied['flow_iat_mean'] * (1 + timing_noise)
# --- END OF DATA AUGMENTATION ---

# Shuffle the data
df_final = local_multiplied.sample(frac=1, random_state=SEED).reset_index(drop=True)

features = [
    'dest_port', 'is_privileged_port', 'protocol', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
    'pkt_len_mean', 'flow_iat_mean', 'down_up_ratio',
    'fin_flag', 'syn_flag', 'rst_flag', 'psh_flag', 'ack_flag'
]

# Ensure numeric types
for col in features:
    df_final[col] = pd.to_numeric(df_final[col], errors='coerce')
df_final.dropna(inplace=True)

data = df_final[features].values

# Scale the data
scaler = RobustScaler()
scaled_data = scaler.fit_transform(data)
data_tensor = torch.FloatTensor(scaled_data)

# --- TRAINING SETUP ---
cyber_ai = CyberAI(input_dim=13)  # Matches our new 13 features
criterion = nn.MSELoss()
optimizer = optim.Adam(cyber_ai.model.parameters(), lr=0.001)  # Slightly faster learning rate

dataset = TensorDataset(data_tensor, data_tensor)
loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

print(f"Training on Pure Local Data: {len(data_tensor)} rows...")

cyber_ai.model.train()
for epoch in range(EPOCHS):
    epoch_loss = 0.0
    for batch_x, _ in loader:
        optimizer.zero_grad()
        output = cyber_ai.model(batch_x)
        loss = criterion(output, batch_x)
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()

    if (epoch + 1) % 5 == 0:
        avg_loss = epoch_loss / len(loader)
        print(f"   -> Epoch [{epoch + 1}/{EPOCHS}], Loss: {avg_loss:.6f}")

# --- THRESHOLD CALCULATION ---
cyber_ai.model.eval()
with torch.no_grad():
    reconstructed = cyber_ai.model(data_tensor)
    errors = torch.mean((data_tensor - reconstructed) ** 2, dim=1).numpy()

    max_normal_error = np.max(errors)
    cyber_ai.threshold = max_normal_error * 1.10


cyber_ai.scaler = scaler
cyber_ai.save()

print(f"\nAI Successfully Trained on Pure Local Data!")
print(f"Server Alert Threshold Locked At: {cyber_ai.threshold:.6f}")