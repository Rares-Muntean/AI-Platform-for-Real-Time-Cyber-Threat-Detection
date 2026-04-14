import torch
import numpy as np
from torch.utils.data import DataLoader, TensorDataset


def train_model(cyber_ai, data_tensor, criterion, optimizer, scaler, epochs=20, batch_size=4096):
    """
    Trains the autoencoder using Mini-Batch Gradient Descent to prevent exploding gradients.
    """
    # 1. Create a DataLoader to split the massive dataset into mini-batches
    dataset = TensorDataset(data_tensor, data_tensor)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    print(f"Starting training on {len(data_tensor)} rows with batch size {batch_size}...")

    cyber_ai.model.train()
    for epoch in range(epochs):
        epoch_loss = 0.0

        # Train in batches of 4096
        for batch_x, _ in loader:
            optimizer.zero_grad()
            output = cyber_ai.model(batch_x)
            loss = criterion(output, batch_x)
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()

        # Print average loss for the epoch
        if (epoch + 1) % 1 == 0:
            avg_loss = epoch_loss / len(loader)
            print(f"Epoch[{epoch + 1}/{epochs}], Loss: {avg_loss:.6f}")

    # 2. Calculate Threshold (also in batches so we don't crash the RAM)
    print("Calculating anomaly threshold...")
    with torch.no_grad():
        cyber_ai.model.eval()
        all_errors = []

        # Test loader (no shuffling needed)
        test_loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

        for batch_x, _ in test_loader:
            reconstructed = cyber_ai.model(batch_x)
            errors = torch.mean((batch_x - reconstructed) ** 2, dim=1).numpy()
            all_errors.extend(errors)

        cyber_ai.threshold = np.percentile(all_errors, 99)

    cyber_ai.scaler = scaler
    cyber_ai.save()
    print(f"Model trained successfully! Threshold set to: {cyber_ai.threshold:.6f}")