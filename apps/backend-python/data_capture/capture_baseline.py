import os
import time
from collections import deque

import pandas as pd
import numpy as np
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# CONFIG
FLOW_TIMEOUT = 30
PACKET_LIMIT = 50
active_flows = {}
collected_features = []

base_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(base_dir, ".."))
save_dir = os.path.join(project_root, "datasets")
if not os.path.exists(save_dir):
    os.makedirs(save_dir)
save_path = os.path.join(save_dir, "local_calibration.csv")

def monitor_traffic(packet):
    if packet.haslayer(IP):
        now = time.time()
        src_ip, dst_ip, proto = packet[IP].src, packet[IP].dst, packet.proto
        sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
        dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)
        pkt_len = len(packet)

        if sport < 1024 and dport >= 1024:
            forward_key = (dst_ip, src_ip, dport, sport, proto)
            backward_key = (src_ip, dst_ip, sport, dport, proto)
            actual_dport = sport
        else:
            forward_key = (src_ip, dst_ip, sport, dport, proto)
            backward_key = (dst_ip, src_ip, dport, sport, proto)
            actual_dport = dport

        if forward_key in active_flows:
            flow_key, is_forward = forward_key, True
        elif backward_key in active_flows:
            flow_key, is_forward = backward_key, False
        else:
            flow_key, is_forward = forward_key, True
            active_flows[flow_key] = {
                'start_time': now, 'last_time': now, 'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0, 'flags': "", 'dport': actual_dport, 'proto': proto
            }

        flow = active_flows[flow_key]

        if is_forward:
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += len(packet)
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += len(packet)

        flow['last_time'] = now
        if packet.haslayer(TCP): flow['flags'] += str(packet[TCP].flags)

        is_done = (flow['fwd_pkts'] + flow['bwd_pkts']) >= PACKET_LIMIT
        if packet.haslayer(TCP):
            if 'F' in str(packet[TCP].flags) or 'R' in str(packet[TCP].flags): is_done = True

        if is_done:
            fwd_pkts, bwd_pkts = max(1, flow['fwd_pkts']), max(1, flow['bwd_pkts'])
            total_pkts = fwd_pkts + bwd_pkts
            duration = max(flow['last_time'] - flow['start_time'], 0.0001)
            is_privileged_port = 1 if flow['dport'] < 1024 else 0

            # Features
            feat = [
                np.log1p(flow['dport']),
                is_privileged_port,
                flow['proto'],
                np.log1p(flow['fwd_bytes'] / fwd_pkts),
                np.log1p(flow['bwd_bytes'] / bwd_pkts),
                np.log1p((flow['fwd_bytes'] + flow['bwd_bytes']) / total_pkts),
                np.log1p((duration / max(1, total_pkts - 1)) * 1_000_000),
                flow['bwd_bytes'] / max(1, flow['fwd_bytes']),
                1 if 'F' in flow['flags'] else 0,
                1 if 'S' in flow['flags'] else 0,
                1 if 'R' in flow['flags'] else 0,
                1 if 'P' in flow['flags'] else 0,
                1 if 'A' in flow['flags'] else 0,
            ]
            collected_features.append(feat)
            print(f"Captured Flow #{len(collected_features)}", end='\r')
            del active_flows[flow_key]

try:
    sniff(prn=monitor_traffic, store=0, filter="ip")
except KeyboardInterrupt:
    print("\nSniffing stopped by user.")
finally:
    if len(collected_features) > 0:
        cols = ['dest_port', 'is_privileged_port', 'protocol', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'pkt_len_mean', 'flow_iat_mean',
                'down_up_ratio', 'fin_flag', 'syn_flag', 'rst_flag', 'psh_flag', 'ack_flag']
        df = pd.DataFrame(collected_features, columns=cols)

        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(current_dir, '..'))
        datasets_dir = os.path.join(project_root, 'datasets')

        os.makedirs(datasets_dir, exist_ok=True)

        save_path = os.path.join(datasets_dir, 'local_calibration.csv')
        df.to_csv(save_path, index=False)

        print(f"\n SUCCESSFULLY SAVED {len(df)} flows to:\n{save_path}")
    else:
        print("\n No flows captured. Nothing saved.")