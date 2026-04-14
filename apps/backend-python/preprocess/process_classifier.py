import numpy as np
import pandas as pd
import os

input_files = [
    "E:/A.Projects/PROJECTS-LICENTA/02-22-2018.csv",  # Web attacks / Brute Force
    "E:/A.Projects/PROJECTS-LICENTA/02-23-2018.csv",  # Brute Force (Web/XSS)
    "E:/A.Projects/PROJECTS-LICENTA/02-20-2018.csv",  # DDoS
    "E:/A.Projects/PROJECTS-LICENTA/02-14-2018.csv",  # BruteForce
    "E:/A.Projects/PROJECTS-LICENTA/02-15-2018.csv",
    "E:/A.Projects/PROJECTS-LICENTA/02-16-2018.csv",
    "E:/A.Projects/PROJECTS-LICENTA/02-21-2018.csv",
    "E:/A.Projects/PROJECTS-LICENTA/02-28-2018.csv",
    "E:/A.Projects/PROJECTS-LICENTA/03-01-2018.csv",
    "E:/A.Projects/PROJECTS-LICENTA/03-02-2018.csv",
]
output_file = "../datasets/classifier_data.csv"

target_columns = [
    'Dst Port', 'Protocol', 'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean',
    'Pkt Len Mean', 'Flow IAT Mean', 'Down/Up Ratio',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt',
    'Label'
]

# We will grab 500,000 Benign, and ALL the attacks we can find
max_benign = 500000
benign_count = 0
data_list = []

for file_path in input_files:
    if not os.path.exists(file_path): continue
    print(f"\nOpening {os.path.basename(file_path)}...")

    for chunk in pd.read_csv(file_path, chunksize=500000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        try:
            chunk = chunk[target_columns]
        except KeyError:
            continue

        # --- THE FIX IS HERE ---
        # 1. Force all feature columns to be numbers. If it's text (like a repeated header), turn it into NaN.
        features_only = target_columns[:-1]  # Everything except 'Label'
        for col in features_only:
            chunk[col] = pd.to_numeric(chunk[col], errors='coerce')

        # 2. Drop all rows that got turned into NaN or were broken
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.dropna(inplace=True)

        # 3. Clip negative values to 0 (Fixes the dataset glitch of negative packet times/lengths)
        for col in features_only:
            chunk[col] = chunk[col].clip(lower=0)
        # -----------------------

        # 1. Grab Attacks (Keep all of them)
        attacks = chunk[chunk['Label'] != 'Benign'].copy()

        # Group attacks so the AI doesn't get confused by 50 different micro-labels
        attacks['Label'] = attacks['Label'].replace({
            'FTP-BruteForce': 'BruteForce',
            'SSH-Bruteforce': 'BruteForce',
            'DoS attacks-Hulk': 'DoS',
            'DoS attacks-SlowHTTPTest': 'DoS',
            'DoS attacks-GoldenEye': 'DoS',
            'DoS attacks-Slowloris': 'DoS',
            'DDOS attack-HOIC': 'DoS',
            'DDOS attack-LOIC-UDP': 'DoS',
            'Brute Force -Web': 'WebAttack',
            'Brute Force -XSS': 'WebAttack',
            'SQL Injection': 'WebAttack',
            'Infilteration': 'Infiltration',
            'Bot': 'Botnet'
        })

        # 2. Grab Benign (Until we hit 500k)
        benign = chunk[chunk['Label'] == 'Benign'].copy()
        if benign_count < max_benign:
            benign = benign.head(max_benign - benign_count)
            benign_count += len(benign)
        else:
            benign = pd.DataFrame()  # Empty if we have enough

        combined_chunk = pd.concat([benign, attacks])

        if not combined_chunk.empty:
            processed = pd.DataFrame()
            # MUST APPLY THE SAME MATH AS YOUR SNIFFER!
            processed['dest_port'] = np.log1p(combined_chunk['Dst Port'])
            processed['protocol'] = combined_chunk['Protocol']
            processed['fwd_pkt_len_mean'] = np.log1p(combined_chunk['Fwd Pkt Len Mean'])
            processed['bwd_pkt_len_mean'] = np.log1p(combined_chunk['Bwd Pkt Len Mean'])
            processed['pkt_len_mean'] = np.log1p(combined_chunk['Pkt Len Mean'])
            processed['flow_iat_mean'] = np.log1p(combined_chunk['Flow IAT Mean'])
            processed['down_up_ratio'] = combined_chunk['Down/Up Ratio']
            processed['fin_flag'] = combined_chunk['FIN Flag Cnt'].clip(upper=1)
            processed['syn_flag'] = combined_chunk['SYN Flag Cnt'].clip(upper=1)
            processed['rst_flag'] = combined_chunk['RST Flag Cnt'].clip(upper=1)
            processed['psh_flag'] = combined_chunk['PSH Flag Cnt'].clip(upper=1)
            processed['ack_flag'] = combined_chunk['ACK Flag Cnt'].clip(upper=1)
            processed['Label'] = combined_chunk['Label']  # KEEP THE LABEL!

            data_list.append(processed)
            print(f"Extracted -> Benign: {benign_count} | Total Rows in memory: {sum(len(x) for x in data_list)}",
                  end='\r')

master_df = pd.concat(data_list)
master_df.to_csv(output_file, index=False)
print(f"\n\n✅ Classifier Dataset saved! Rows: {len(master_df)}")
print("\n--- DATASET ATTACK DISTRIBUTION ---")
print(master_df['Label'].value_counts())