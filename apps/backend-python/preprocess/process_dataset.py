import numpy as np
import pandas as pd

input_file = "E:/NF-UQ-NIDS-v2.csv/NF-UQ-NIDS-v2.csv"
output_file = "../datasets/master_normal_traffic.csv"

selected_cols = [
    'L4_DST_PORT', 'LONGEST_FLOW_PKT', 'FLOW_DURATION_MILLISECONDS',
    'TCP_FLAGS', 'MIN_TTL', 'TCP_WIN_MAX_OUT', 'Label', 'IN_PKTS', 'OUT_PKTS', 'IN_BYTES', 'OUT_BYTES'
]

target_per_chunk = 10000
normal_data_list = []
total_extracted = 0

for i, chunk in enumerate(pd.read_csv(input_file, usecols=selected_cols, chunksize=750000)):
    benign_pool = chunk[chunk['Label'] == 0].copy()

    if not benign_pool.empty:
        sample_n = min(len(benign_pool), target_per_chunk)
        benign_chunk = benign_pool.sample(n=sample_n, random_state=42)

        # EXTRACT IMPORTANT FEATURES
        flags = benign_chunk['TCP_FLAGS'].astype(int)
        benign_chunk['is_syn'] = (flags & 2).astype(bool).astype(int)
        benign_chunk['is_ack'] = (flags & 16).astype(bool).astype(int)
        benign_chunk['is_rst'] = (flags & 4).astype(bool).astype(int)
        benign_chunk['is_fin'] = (flags & 1).astype(bool).astype(int)

        benign_chunk['dest_port'] = np.log1p(benign_chunk['L4_DST_PORT'])
        benign_chunk['packet_size'] = np.log1p(benign_chunk['LONGEST_FLOW_PKT'])
        benign_chunk['time_delta'] = np.log1p(benign_chunk['FLOW_DURATION_MILLISECONDS'] / 1000.0)
        benign_chunk['ttl'] = benign_chunk['MIN_TTL']
        benign_chunk['tcp_window'] = np.log1p(benign_chunk['TCP_WIN_MAX_OUT'])
        benign_chunk['payload_len'] = np.log1p(benign_chunk['IN_BYTES'])

        # Payload Ratio
        header_estimate = benign_chunk["IN_PKTS"] * 54
        payload_estimate = (benign_chunk["IN_BYTES"] - header_estimate).clip(lower=0)
        benign_chunk['payload_ratio'] = payload_estimate / benign_chunk["IN_BYTES"].clip(lower=1)

        # Bytes Per Second (Throughput)
        duration_sec = benign_chunk['FLOW_DURATION_MILLISECONDS'] / 1000
        benign_chunk['bps'] = np.log1p(benign_chunk['IN_BYTES'] / duration_sec.clip(lower=0.001))

        # Incoming vs Outgoing packet difference
        benign_chunk['pkts_count'] = benign_chunk['IN_PKTS']

        # Average Packet Size in the flow
        benign_chunk['avg_pkt_size'] = benign_chunk['IN_BYTES'] / benign_chunk['IN_PKTS'].clip(lower=1)

        # Processing Final Selected Columns
        final_cols = ['dest_port', 'packet_size', 'time_delta', 'is_syn', 'is_ack', 'is_rst', 'is_fin', 'ttl',
                      'tcp_window', 'payload_len', 'payload_ratio', 'bps', 'pkts_count', 'avg_pkt_size']
        normal_data_list.append(benign_chunk[final_cols])
        total_extracted += len(benign_chunk)
        print(f"Processed Chunk {i + 1} | Extracted: {total_extracted} rows", end='\r')

    if total_extracted >= 1000000:
        break

master_df = pd.concat(normal_data_list)[:1000000]
master_df.to_csv(output_file, index=False)
print("Master Normal Dataset Created!")