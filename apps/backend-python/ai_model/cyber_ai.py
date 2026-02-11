import torch
import torch.nn as nn
import joblib
import os


class Autoencoder(nn.Module):
     def __init__(self, input_dim):
         super(Autoencoder, self).__init__()

         self.encoder = nn.Sequential(
             nn.Linear(input_dim, 24),
             nn.BatchNorm1d(24),
             nn.ReLU(),
             nn.Linear(24, 12),
             nn.ReLU(),
             nn.Linear(12, 4),
         )

         self.decoder = nn.Sequential(
             nn.Linear(4, 12),
             nn.ReLU(),
             nn.Linear(12, 24),
             nn.ReLU(),
             nn.Linear(24, input_dim),
             nn.Sigmoid()
         )

     def forward(self, x):
         x = self.encoder(x)
         x = self.decoder(x)
         return x

class CyberAI:
    ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # backend-python folder
    MODEL_DIR = os.path.join(ROOT_DIR, 'models')
    MODEL_PATH = os.path.join(MODEL_DIR, 'model.pth')
    SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')
    THRESHOLD_PATH = os.path.join(MODEL_DIR, 'threshold.txt')

    def __init__(self, input_dim = 14):
        self.model = Autoencoder(input_dim)
        self.scaler = None
        self.threshold  = 0.0

    def save(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        torch.save(self.model.state_dict(), model_path)
        joblib.dump(self.scaler, scaler_path)
        with open(self.THRESHOLD_PATH, "w") as f:
            f.write(str(self.threshold))

    def load(self, model_path=MODEL_PATH, scaler_path=SCALER_PATH):
        self.scaler = joblib.load(scaler_path)
        self.model.load_state_dict(torch.load(model_path))
        self.model.eval()
        with open(self.THRESHOLD_PATH, "r") as f:
            self.threshold = float(f.read())

    def get_anomaly_score(self, data_point):
        scaled_data = self.scaler.transform(data_point)
        input_tensor = torch.FloatTensor(scaled_data)

        with torch.no_grad():
            output = self.model(input_tensor)
            loss = torch.mean((input_tensor - output)**2)

        return loss.item()














