import pandas as pd
import numpy as np
from model_logic import CyberAI

brain = CyberAI()
brain.load("models/model.pth", "models/scaler.pkl")

df_attack = pd.read_csv("datasets/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
df_attack.columns = df_attack.columns.str.strip()

selected = [
    'L4_DST_PORT', 'LONGEST_FLOW_PKT', 'FLOW_DURATION_MILLISECONDS',
    'TCP_FLAGS', 'MIN_TTL', 'TCP_WIN_MAX_OUT',
    'IN_BYTES', 'Label'
]

df_only_ddos = df_attack[df_attack['Label'] == 'DDoS']
df_only_benign = df_attack[df_attack['Label'] == 'BENIGN']

def get_score(df_slice, row_idx, is_ddos=False):
    row = df_slice[selected].iloc[row_idx].copy()

    row['Flow IAT Mean'] = np.log1p(row['Flow IAT Mean'] / 1_000_000)
    row['Max Packet Length'] = np.log1p(row['Max Packet Length'])
    row['Init_Win_bytes_forward'] = np.log1p(row['Init_Win_bytes_forward'])
    row['Fwd Header Length'] = np.log1p(row['Fwd Header Length'])

    val = row.values.reshape(1, -1)
    anomaly_score = brain.get_anomaly_score(val)

    if is_ddos:
        simulated_pps = 2000
        anomaly_score *= np.log10(simulated_pps)

    return anomaly_score

print(f"Threshold: {brain.threshold}")

print("\n--- Testing 5 NORMAL Rows ---")
for i in range(5):
    print(f"Score: {get_score(df_only_benign, i, is_ddos=False):.6f} | BENIGN")

print("\n--- Testing 5 DDoS Rows (With PPS Boost) ---")
for i in range(50):
    print(f"Score: {get_score(df_only_ddos, i, is_ddos=True):.6f} | DDoS 🔥")