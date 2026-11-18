from datetime import datetime, timezone
import os
import random
import threading
import time

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset

from ai_model.cyber_ai import CyberAI

FEATURE_COLS = [
    "dest_port",
    "is_privileged_port",
    "protocol",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "pkt_len_mean",
    "flow_iat_mean",
    "down_up_ratio",
    "fin_flag",
    "syn_flag",
    "rst_flag",
    "psh_flag",
    "ack_flag",
]

class AutoCalibrator:

    def __init__(self, guard: CyberAI, min_flows: int = 5):
        self.guard = guard
        self.min_flows = min_flows
        self.memory_path = os.path.join(CyberAI.MODEL_DIR, "local_memory.csv")

        self.state_lock = threading.Lock()
        self.guard_lock = threading.Lock()

        self.status = "idle" # | "recording" | "training"
        self.mode = "update" # | "replace"
        self.samples = []
        self.recording_end_time = 0.0

        self.last_result = None
        self.last_message = None
        self.last_calibrated_at = None


    def is_recording(self) -> bool:
        with self.state_lock:
            return self.status == "recording"

    def record_sample(self, feature_row):
        with self.state_lock:
            if self.status != "recording":
                return

            row = np.asarray(feature_row, dtype=float).tolist()
            self.samples.append(row)

    def get_status(self) -> dict:
        with self.state_lock:
            remaining = 0
            if self.status == "recording":
                remaining = max(0, int(round(self.recording_end_time - time.time())))

            return {
                "status": self.status,
                "mode": self.mode,
                "recordedFlows": len(self.samples),
                "secondsRemaining": remaining,
                "lastResult": self.last_result,
                "lastMessage": self.last_message,
                "lastCalibratedAt": self.last_calibrated_at
            }

    def start_calibration(self, duration: int = 30, mode: str = "update"):
        with self.state_lock:
            if self.status != "idle":
                return False, f"Calibration in progress ({self.status})"

            self.status = "recording"
            self.mode = mode
            self.samples = []
            self.recording_end_time = time.time() + duration
            self.last_result = None
            self.last_message = f"Recording safe traffic for {duration}s ({mode} mode)"

            threading.Thread(
                target=self._worker, args=(duration, mode), daemon=True
            ).start()

            return True, self.last_message

    def _worker(self, duration: int, mode: str):
        while time.time() < self.recording_end_time:
            time.sleep(0.5)

        with self.state_lock:
            captured = list(self.samples)
            if len(captured) < self.min_flows:
                self.status = "idle"
                self.last_result = "error"
                self.last_message = f"Captured the minimum of {self.min_flows} flows. Exiting"
                print(f"[CALIBRATION] {self.last_message}")
                return

            self.status = "training"
            print(f"[CALIBRATION] Recording finished ({len(captured)}), starting training")

        try:
            new_threshold = self._train_and_reload(captured, mode)
            with self.state_lock:
                self.status = "idle"
                self.last_result = "success"
                self.last_calibrated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                self.last_message = f"Calibration completed with {len(captured)} new flows. Threshold: {new_threshold:.6f}"
        except Exception as e:
            with self.state_lock:
                self.status = "idle"
                self.last_result = "error"
                self.last_message = f"Training failed: {e}"
                print(f"[CALIBRATION ERROR] {e}")

    def _augment_dataframe(self, df: pd.DataFrame, target_rows: int = 3000):
        heavy = df[df["dest_port"] >= 4.0]
        light = df[df["dest_port"] < 4.0]

        parts = []
        if not heavy.empty and not light.empty:
            h_rep = max(1, (target_rows // 2) // len(heavy))
            l_rep = max(1, (target_rows // 2) // len(light))
            parts.append(pd.concat([heavy] * h_rep, ignore_index=True))
            parts.append(pd.concat([light] * l_rep, ignore_index=True))
        else:
            rep = max(1, target_rows // len(df))
            parts.append(pd.concat([df] * rep, ignore_index=True))

        df_aug = pd.concat(parts, ignore_index=True)
        if len(df_aug) > target_rows:
            df_aug = df_aug.sample(n=target_rows, random_state=42).reset_index(
                drop=True
            )

        for col in ["fwd_pkt_len_mean", "bwd_pkt_len_mean", "pkt_len_mean"]:
            noise = np.random.uniform(-0.15, 0.15, size=len(df_aug))
            df_aug[col] = df_aug[col] * (1 + noise)

        timing_noise = np.random.uniform(-0.10, 2.00, size=len(df_aug))
        df_aug["flow_iat_mean"] = df_aug["flow_iat_mean"] * (1 + timing_noise)

        return df_aug.sample(frac=1, random_state=42).reset_index(drop=True)

    def _train_and_reload(self, captured_flows: list, mode: str):
        torch.set_num_threads(1)
        random.seed(42)
        np.random.seed(42)
        torch.manual_seed(42)

        df_new = pd.DataFrame(captured_flows, columns=FEATURE_COLS)
        os.makedirs(CyberAI.MODEL_DIR, exist_ok=True)

        temp_ai = CyberAI()

        if mode == "replace":
            df_new.to_csv(self.memory_path, index=False)
            df_train_source = df_new
            scaler = RobustScaler()
            epochs = 30
            lr = 0.001
            old_threshold = 0.0
        else:
            temp_ai.load()
            old_threshold = temp_ai.threshold
            scaler = temp_ai.scaler
            epochs = 15
            lr = 0.0002

            if os.path.exists(self.memory_path):
                df_old = pd.read_csv(self.memory_path).dropna()
                df_combined = pd.concat([df_old, df_new], ignore_index=True).tail(5000)
                df_combined.to_csv(self.memory_path, index=False)

                replay_n = min(len(df_old), max(100, len(df_new) * 2))
                df_replay = df_old.sample(n=replay_n, random_state=42)
                df_train_source = pd.concat([df_new, df_replay], ignore_index=True)
            else:
                df_new.to_csv(self.memory_path, index=False)
                df_train_source = df_new

        df_final = self._augment_dataframe(df_train_source, target_rows=3000)
        data = df_final[FEATURE_COLS].values

        if mode == "replace":
            scaled_data = scaler.fit_transform(data)
        else:
            scaled_data = scaler.transform(data)

        data_tensor = torch.FloatTensor(scaled_data)
        batch_size = min(256, len(data_tensor))
        dataset = TensorDataset(data_tensor, data_tensor)
        loader = DataLoader(
            dataset, batch_size=batch_size, shuffle=True, drop_last=True
        )

        criterion = nn.MSELoss()
        optimizer = optim.Adam(temp_ai.model.parameters(), lr=lr)

        temp_ai.model.train()
        for epoch in range(epochs):
            epoch_loss = 0.0
            for batch_x, _ in loader:
                optimizer.zero_grad()
                output = temp_ai.model(batch_x)
                loss = criterion(output, batch_x)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()

            if (epoch + 1) % 5 == 0:
                print(
                    f"[CALIBRATE] Epoch [{epoch + 1}/{epochs}], Loss:"
                    f" {epoch_loss / len(loader):.6f}"
                )

        temp_ai.model.eval()
        with torch.no_grad():
            reconstructed = temp_ai.model(data_tensor)
            errors = torch.mean((data_tensor - reconstructed) ** 2, dim=1).numpy()
            new_threshold = float(np.max(errors) * 1.10)

        if mode == "update":
            temp_ai.threshold = max(old_threshold, new_threshold)
        else:
            temp_ai.threshold = new_threshold

        temp_ai.scaler = scaler
        temp_ai.save()

        with self.guard_lock:
            self.guard.load()

        return self.guard.threshold