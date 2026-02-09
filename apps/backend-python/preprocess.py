import numpy as np
import pandas as pd

input_file = "E:/NF-UQ-NIDS-v2.csv/NF-UQ-NIDS-v2.csv"
output_file = "datasets/master_normal_traffic.csv"

selected_cols = [
    'L4_DST_PORT', 'LONGEST_FLOW_PKT', 'FLOW_DURATION_MILLISECONDS',
    'TCP_FLAGS', 'MIN_TTL', 'TCP_WIN_MAX_OUT',
    'IN_BYTES', 'Label'
]

normal_data_list = []
max_rows = 1000000
for chunk in pd.read_csv(input_file, usecols=selected_cols, chunksize=100000):
    benign_chunk = chunk[chunk['Label'] == 0].copy()

    if not benign_chunk.empty:
        flags = benign_chunk['TCP_FLAGS'].astype(int)
        benign_chunk['is_syn'] = (flags & 2).astype(bool).astype(int)
        benign_chunk['is_ack'] = (flags & 16).astype(bool).astype(int)
        benign_chunk['is_rst'] = (flags & 4).astype(bool).astype(int)
        benign_chunk['is_fin'] = (flags & 1).astype(bool).astype(int)

        # 2. Rename and Scale
        benign_chunk['dest_port'] = benign_chunk['L4_DST_PORT']
        benign_chunk['packet_size'] = np.log1p(benign_chunk['LONGEST_FLOW_PKT'])
        benign_chunk['time_delta'] = np.log1p(benign_chunk['FLOW_DURATION_MILLISECONDS'] / 1000.0)
        benign_chunk['ttl'] = benign_chunk['MIN_TTL']
        benign_chunk['tcp_window'] = np.log1p(benign_chunk['TCP_WIN_MAX_OUT'])
        benign_chunk['payload_len'] = np.log1p(benign_chunk['IN_BYTES'])

        final_cols = ['dest_port', 'packet_size', 'time_delta', 'is_syn', 'is_ack', 'is_rst', 'is_fin', 'ttl',
                      'tcp_window', 'payload_len']

        normal_data_list.append(benign_chunk[final_cols])

        current_total = sum(len(x) for x in normal_data_list)
        if current_total >= max_rows:
            print(f"Reached {current_total} rows. Stopping.")
            break

master_df = pd.concat(normal_data_list)[:max_rows]
master_df.to_csv(output_file, index=False)
print("Master Normal Dataset Created!")