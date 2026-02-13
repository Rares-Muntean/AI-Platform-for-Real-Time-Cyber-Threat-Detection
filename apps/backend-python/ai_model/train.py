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
data = df[["dest_port", "packet_size", "time_delta", "is_syn", "is_ack", "is_rst", "is_fin", "ttl", "tcp_window",
           "payload_len", "payload_ratio", "bps", "pkts_count", "avg_pkt_size"]].values

scaler = MinMaxScaler()
scaled_data = scaler.fit_transform(data)
data_tensor = torch.FloatTensor(scaled_data)

# TRAINING LOOP
for i in range(1):
    # SEED = 367 -> 0.002515 loss, 0.027671 Threshold, 940 -> 0.002850 loss, 0.028333 threshold
    # SEED = random.randrange(1000)
    SEED = 367
    print(f"Training seed: {SEED}")

    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    torch.cuda.manual_seed_all(SEED)

    cyber_ai = CyberAI()
    criterion = nn.MSELoss()
    optimizer = optim.Adam(cyber_ai.model.parameters(), lr=0.01)

    train_model(cyber_ai, data_tensor, criterion, optimizer, scaler, 250)
    print("\n\n\n")






