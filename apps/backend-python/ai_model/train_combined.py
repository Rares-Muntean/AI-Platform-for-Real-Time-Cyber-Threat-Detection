import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
import random
import os
from sklearn.preprocessing import MinMaxScaler
from torch.utils.data import DataLoader, TensorDataset

# Make sure we import your AI properly
from ai_model.cyber_ai import CyberAI

# --- CONFIG ---
EPOCHS = 20
BATCH_SIZE = 4096
SEED = 42


def set_seeds(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


set_seeds(SEED)

print("1️⃣ Loading datasets...")
# 1. Load CIC-IDS Data
df_cic = pd.read_csv("../datasets/master_normal_traffic.csv")
df_cic.dropna(inplace=True)
print(f"   -> CIC-IDS Base: {len(df_cic)} rows")

# 2. Load Your Local Linux Data
df_local = pd.read_csv("../datasets/local_calibration.csv")
df_local.dropna(inplace=True)
print(f"   -> Local Linux Capture: {len(df_local)} rows")

print("2️⃣ Merging and Oversampling...")
# OVERSAMPLING: We repeat your local data 200 times so the AI doesn't ignore it
local_multiplied = pd.concat([df_local] * 500, ignore_index=True)

# Combine and Shuffle
df_combined = pd.concat([df_cic, local_multiplied], ignore_index=True)
df_combined = df_combined.sample(frac=1, random_state=SEED).reset_index(drop=True)
print(f"   -> Total Training Rows: {len(df_combined)}")

features = [
    'dest_port', 'protocol', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
    'pkt_len_mean', 'flow_iat_mean', 'down_up_ratio',
    'fin_flag', 'syn_flag', 'rst_flag', 'psh_flag', 'ack_flag'
]

# Ensure everything is numeric
for col in features:
    df_combined[col] = pd.to_numeric(df_combined[col], errors='coerce')
df_combined.dropna(inplace=True)

data = df_combined[features].values

print("3️⃣ Scaling data...")
scaler = MinMaxScaler()
scaled_data = scaler.fit_transform(data)
data_tensor = torch.FloatTensor(scaled_data)

# --- TRAINING SETUP ---
cyber_ai = CyberAI(input_dim=12)
criterion = nn.MSELoss()
optimizer = optim.Adam(cyber_ai.model.parameters(), lr=0.001)

dataset = TensorDataset(data_tensor, data_tensor)
loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

print("4️⃣ Beginning PyTorch Training...")
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

    avg_loss = epoch_loss / len(loader)
    print(f"   -> Epoch [{epoch + 1}/{EPOCHS}], Loss: {avg_loss:.6f}")

print("5️⃣ Calculating Strict Server Threshold...")
# We use ONLY the local data to set the threshold, so it's perfectly tuned to your VM!
local_scaled = scaler.transform(df_local[features].values)
local_tensor = torch.FloatTensor(local_scaled)

with torch.no_grad():
    cyber_ai.model.eval()
    reconstructed = cyber_ai.model(local_tensor)
    errors = torch.mean((local_tensor - reconstructed) ** 2, dim=1).numpy()

    # Allow 1% margin of error for normal traffic variations
    cyber_ai.threshold = np.percentile(errors, 99)

# SAVE
cyber_ai.scaler = scaler
cyber_ai.save()
print(f"\n✅ AI Successfully Trained!")
print(f"🔒 Server Alert Threshold Locked At: {cyber_ai.threshold:.6f}")