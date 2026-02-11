import torch
import numpy as np

def train_model(cyber_ai, data_tensor, criterion, optimizer, scaler, epochs=300):
    """
    Trains the autoencoder model based on a number of epochs, saving the calculated threshold and the model inside the
    'models' folder.

    :param cyber_ai: AI model object.
    :param data_tensor: Data columns transformed to tensors.
    :param criterion: Criterion type (e.g. MSELoss()).
    :param optimizer: Optimizer chosen (e.g. Adam()).
    :param scaler: Scaler chosen (e.g. MinMaxScaler()).
    :param epochs: Number of epochs for training.
    :return: None -> saves the model and the scaler inside the 'models' folder
    """

    for epoch in range(epochs):
        output = cyber_ai.model(data_tensor)
        loss = criterion(output, data_tensor)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        if (epoch + 1) % 10 == 0:
            print(f"Epoch[{epoch + 1}/{epochs}], Loss: {loss.item():.6f}")

    with torch.no_grad():
        cyber_ai.model.eval()
        reconstructed = cyber_ai.model(data_tensor)
        errors = torch.mean((data_tensor - reconstructed) ** 2, dim=1).numpy()

        cyber_ai.threshold = np.percentile(errors, 99)

    cyber_ai.scaler = scaler
    cyber_ai.save()
    print(f"Model trained. Threshold set to: {cyber_ai.threshold:.6f}")
