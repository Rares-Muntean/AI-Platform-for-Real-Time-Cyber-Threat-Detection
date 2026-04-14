import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
import random
from sklearn.preprocessing import MinMaxScaler
from ai_model.cyber_ai import CyberAI
from ai_model.training import train_model

df = pd.read_csv("../datasets/master_normal_traffic.csv")

# Clean any rogue NaNs that Pandas might have accidentally read
df.dropna(inplace=True)

features = [
    'dest_port', 'protocol', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean',
    'pkt_len_mean', 'flow_iat_mean', 'down_up_ratio',
    'fin_flag', 'syn_flag', 'rst_flag', 'psh_flag', 'ack_flag'
]
data = df[features].values

scaler = MinMaxScaler()
scaled_data = scaler.fit_transform(data)
data_tensor = torch.FloatTensor(scaled_data)

# TRAINING LOOP
for i in range(1):
    SEED = 367
    print(f"Training seed: {SEED}")

    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    torch.cuda.manual_seed_all(SEED)

    cyber_ai = CyberAI()
    criterion = nn.MSELoss()

    # REDUCED LEARNING RATE TO 0.001 TO PREVENT NaN EXPLOSIONS
    optimizer = optim.Adam(cyber_ai.model.parameters(), lr=0.001)

    # REDUCED EPOCHS TO 20 AND PASSED BATCH SIZE
    train_model(cyber_ai, data_tensor, criterion, optimizer, scaler, epochs=20, batch_size=4096)
    print("\n\n\n")