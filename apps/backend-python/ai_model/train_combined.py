import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
import random
from sklearn.preprocessing import RobustScaler
from torch.utils.data import DataLoader, TensorDataset

from ai_model.cyber_ai import CyberAI

EPOCHS = 20
BATCH_SIZE = 4096
SEED = 42


def set_seeds(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


set_seeds(SEED)

df_cic = pd.read_csv("../datasets/master_normal_traffic.csv")
df_cic.dropna(inplace=True)

df_local = pd.read_csv("../datasets/local_calibration.csv")
df_local.dropna(inplace=True)

local_multiplied = pd.concat([df_local] * 500, ignore_index=True)

df_combined = pd.concat([df_cic, local_multiplied], ignore_index=True)
df_combined = df_combined.sample(frac=1, random_state=SEED).reset_index(drop=True)

features = [
    'dest_port', 'protocol', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
    'pkt_len_mean', 'flow_iat_mean', 'down_up_ratio',
    'fin_flag', 'syn_flag', 'rst_flag', 'psh_flag', 'ack_flag'
]

for col in features:
    df_combined[col] = pd.to_numeric(df_combined[col], errors='coerce')
df_combined.dropna(inplace=True)

data = df_combined[features].values

scaler = RobustScaler()
scaled_data = scaler.fit_transform(data)
data_tensor = torch.FloatTensor(scaled_data)

# --- TRAINING SETUP ---
cyber_ai = CyberAI(input_dim=12)
criterion = nn.MSELoss()
optimizer = optim.Adam(cyber_ai.model.parameters(), lr=0.0001)

dataset = TensorDataset(data_tensor, data_tensor)
loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

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

local_scaled = scaler.transform(df_local[features].values)
local_tensor = torch.FloatTensor(local_scaled)

with torch.no_grad():
    cyber_ai.model.eval()
    reconstructed = cyber_ai.model(local_tensor)
    errors = torch.mean((local_tensor - reconstructed) ** 2, dim=1).numpy()

    cyber_ai.threshold = np.percentile(errors, 99)

cyber_ai.scaler = scaler
cyber_ai.save()
print(f"\nAI Successfully Trained!")
print(f"Server Alert Threshold Locked At: {cyber_ai.threshold:.6f}")