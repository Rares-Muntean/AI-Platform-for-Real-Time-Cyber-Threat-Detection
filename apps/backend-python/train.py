import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
import random
from sklearn.preprocessing import MinMaxScaler
from model_logic import CyberAI

# seed = 42
# torch.manual_seed(seed)
# np.random.seed(seed)
# random.seed(seed)
# if torch.cuda.is_available():
#     torch.cuda.manual_seed(seed)

df = pd.read_csv("datasets/master_normal_traffic.csv")
data = df[["dest_port", "packet_size", "time_delta", "is_syn", "is_ack", "is_rst", "is_fin", "ttl", "tcp_window", "payload_len"]].values

scaler = MinMaxScaler()
scaled_data = scaler.fit_transform(data)
data_tensor = torch.FloatTensor(scaled_data)

cyber_ai = CyberAI(input_dim=10)
criterion = nn.MSELoss()
optimizer = optim.Adam(cyber_ai.model.parameters(), lr=0.01)

# TRAINING LOOP
print("Training autoencoder model...")
epochs = 200
for epoch in range (epochs):
    output = cyber_ai.model(data_tensor)
    loss = criterion(output, data_tensor)

    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

    if (epoch+1) % 10 == 0:
        print(f"Epoch[{epoch+1}/{epochs}], Loss: {loss.item():.6f}"

        )
with torch.no_grad():
    cyber_ai.model.eval()
    reconstructed = cyber_ai.model(data_tensor)
    errors =  torch.mean((data_tensor - reconstructed)**2, dim=1).numpy()

    cyber_ai.threshold = np.percentile(errors, 99)


cyber_ai.scaler = scaler
cyber_ai.save()
print(f"Model trained. Threshold set to: {cyber_ai.threshold:.6f}")







