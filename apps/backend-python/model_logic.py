import torch
import torch.nn as nn
import joblib


class Autoencoder(nn.Module):
     def __init__(self, input_dim):
         super(Autoencoder, self).__init__()

         self.encoder = nn.Sequential(
             nn.Linear(input_dim, 16),
             nn.BatchNorm1d(16),
             nn.ReLU(),
             nn.Linear(16, 8),
             nn.ReLU(),
             nn.Linear(8, 3),
         )

         self.decoder = nn.Sequential(
             nn.Linear(3, 8),
             nn.ReLU(),
             nn.Linear(8, 16),
             nn.ReLU(),
             nn.Linear(16, input_dim),
             nn.Sigmoid()
         )

     def forward(self, x):
         x = self.encoder(x)
         x = self.decoder(x)
         return x

class CyberAI:
    def __init__(self, input_dim = 10):
        self.model = Autoencoder(input_dim)
        self.scaler = None
        self.threshold  = 0.0

    def save(self, model_path="models/model.pth", scaler_path="models/scaler.pkl"):
        torch.save(self.model.state_dict(), model_path)
        joblib.dump(self.scaler, scaler_path)
        with open("models/threshold.txt", "w") as f:
            f.write(str(self.threshold))

    def load(self, model_path="models/model.pth", scaler_path="models/scaler.pkl"):
        self.scaler = joblib.load(scaler_path)
        self.model.load_state_dict(torch.load(model_path))
        self.model.eval()
        with open("models/threshold.txt", "r") as f:
            self.threshold = float(f.read())

    def get_anomaly_score(self, data_point):
        scaled_data = self.scaler.transform(data_point)
        input_tensor = torch.FloatTensor(scaled_data)

        with torch.no_grad():
            output = self.model(input_tensor)
            loss = torch.mean((input_tensor - output)**2)

        return loss.item()














