import numpy as np
import pandas as pd
import os

input_files =[
    "E:/A.Projects/PROJECTS-LICENTA/02-22-2018.csv",
    "E:/A.Projects/PROJECTS-LICENTA/02-23-2018.csv",
    "E:/A.Projects/PROJECTS-LICENTA/02-20-2018.csv",
]
output_file = "../datasets/master_normal_traffic.csv"

target_columns =[
    'Dst Port', 'Protocol', 'Fwd Pkt Len Mean', 'Bwd Pkt Len Mean',
    'Pkt Len Mean', 'Flow IAT Mean', 'Down/Up Ratio',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt',
    'Label'
]

normal_data_list =[]
total_extracted = 0

TARGET_TOTAL = 3000000

for file_path in input_files:
    if total_extracted >= TARGET_TOTAL:
        break

    print(f"\nOpening {os.path.basename(file_path)}...")

    for i, chunk in enumerate(pd.read_csv(file_path, chunksize=750000, low_memory=False)):

        chunk.columns = chunk.columns.str.strip()

        try:
            chunk = chunk[target_columns]
        except KeyError as e:
            print(f"Column mismatch in chunk. Skipping. Error: {e}")
            continue

        benign_pool = chunk[chunk['Label'] == 'Benign'].copy()

        if not benign_pool.empty:
            benign_pool.replace([np.inf, -np.inf], np.nan, inplace=True)
            benign_pool.dropna(inplace=True)

            benign_chunk = benign_pool

            processed_chunk = pd.DataFrame()
            processed_chunk['dest_port'] = np.log1p(benign_chunk['Dst Port'])
            processed_chunk['protocol'] = benign_chunk['Protocol']
            processed_chunk['fwd_pkt_len_mean'] = np.log1p(benign_chunk['Fwd Pkt Len Mean'])
            processed_chunk['bwd_pkt_len_mean'] = np.log1p(benign_chunk['Bwd Pkt Len Mean'])
            processed_chunk['pkt_len_mean'] = np.log1p(benign_chunk['Pkt Len Mean'])
            processed_chunk['flow_iat_mean'] = np.log1p(benign_chunk['Flow IAT Mean'])
            processed_chunk['down_up_ratio'] = benign_chunk['Down/Up Ratio']

            processed_chunk['fin_flag'] = benign_chunk['FIN Flag Cnt'].clip(upper=1)
            processed_chunk['syn_flag'] = benign_chunk['SYN Flag Cnt'].clip(upper=1)
            processed_chunk['rst_flag'] = benign_chunk['RST Flag Cnt'].clip(upper=1)
            processed_chunk['psh_flag'] = benign_chunk['PSH Flag Cnt'].clip(upper=1)
            processed_chunk['ack_flag'] = benign_chunk['ACK Flag Cnt'].clip(upper=1)

            normal_data_list.append(processed_chunk)
            total_extracted += len(processed_chunk)
            print(f"Processed Chunk {i + 1} | Extracted: {total_extracted}/{TARGET_TOTAL} rows", end='\r')

        if total_extracted >= TARGET_TOTAL:
            break

master_df = pd.concat(normal_data_list)[:TARGET_TOTAL]
master_df.to_csv(output_file, index=False)
print(f"\nMaster Normal Dataset Created with {len(master_df)} rows and {len(master_df.columns)} features!")