import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import MinMaxScaler

from model_logic import CyberAI

df = pd.read_csv("datasets/normal_traffic.csv")
data = df[["protocol", "size", "timedelta", "flags"]].values

scaler = MinMaxScaler()
scaled_data = scaler.fit_transform(data)
data_tensor = torch.FloatTensor(scaled_data)

cyber_ai = CyberAI(input_dim=4)
criterion = nn.MSELoss()
optimizer = optim.Adam(cyber_ai.model.parameters(), lr=0.01)

# TRAINING LOOP
print("Training autoencoder model...")
epochs = 100
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
    reconstructed = cyber_ai.model(data_tensor)
    errors =  torch.mean((data_tensor - reconstructed)**2, dim=1)
    cyber_ai.threshold = np.percentile(errors.numpy(), 95)


cyber_ai.scaler = scaler
cyber_ai.save()
print(f"Model trained. Threshold set to: {cyber_ai.threshold}")







