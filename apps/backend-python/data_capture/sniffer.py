import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collections import deque
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from ai_model.cyber_ai import CyberAI
from scapy.all import sniff
import time
import joblib

# Setup AI (Stage 1: The Watchdog)
guard = CyberAI(input_dim=12)
guard.load()
print(f"🛡️ Stage 1: Autoencoder Active. Alert threshold: {guard.threshold:.6f}")

# Setup Classifier (Stage 2: The Investigator)
clf_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'classifier.pkl'))
classifier = joblib.load(clf_path)
print(f"🕵️ Stage 2: Behavioral Classifier Active.")

active_flows = {}
PACKET_LIMIT = 100  # Give human typing more time to look human


def monitor_traffic(packet):
    if packet.haslayer(IP):
        now = time.time()

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet.proto
        sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
        dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)

        # --- STRICT DIRECTIONALITY FIX ---
        # Forces the well-known port to ALWAYS be the destination.
        # This prevents Fwd/Bwd features from randomly flipping!
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
                'start_time': now, 'last_time': now,
                'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0,
                'flags': "", 'dport': actual_dport, 'proto': proto
            }

        flow = active_flows[flow_key]
        pkt_len = len(packet)

        if is_forward:
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += pkt_len
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += pkt_len

        flow['last_time'] = now

        if packet.haslayer(TCP):
            flow['flags'] += str(packet[TCP].flags)
            is_connection_done = 'F' in str(packet[TCP].flags) or 'R' in str(packet[TCP].flags)
        else:
            is_connection_done = False

        total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']

        # End flow if it hits limits
        if total_pkts >= PACKET_LIMIT or is_connection_done:
            predict_flow_threat(flow_key)
            del active_flows[flow_key]


def predict_flow_threat(key):
    flow = active_flows[key]

    fwd_pkts = max(1, flow['fwd_pkts'])
    bwd_pkts = max(1, flow['bwd_pkts'])
    total_pkts = fwd_pkts + bwd_pkts
    duration = max(flow['last_time'] - flow['start_time'], 0.0001)

    dest_port = np.log1p(flow['dport'])
    protocol = flow['proto']
    fwd_pkt_len_mean = np.log1p(flow['fwd_bytes'] / fwd_pkts)
    bwd_pkt_len_mean = np.log1p(flow['bwd_bytes'] / bwd_pkts)
    pkt_len_mean = np.log1p((flow['fwd_bytes'] + flow['bwd_bytes']) / total_pkts)
    iat_mean_seconds = duration / max(1, (total_pkts - 1))
    flow_iat_mean = np.log1p(iat_mean_seconds * 1_000_000)
    down_up_ratio = flow['bwd_bytes'] / max(1, flow['fwd_bytes'])

    fin_flag = 1 if 'F' in flow['flags'] else 0
    syn_flag = 1 if 'S' in flow['flags'] else 0
    rst_flag = 1 if 'R' in flow['flags'] else 0
    psh_flag = 1 if 'P' in flow['flags'] else 0
    ack_flag = 1 if 'A' in flow['flags'] else 0

    # 1. Autoencoder Features (12 features - includes port)
    ae_features = np.array([[dest_port, protocol, fwd_pkt_len_mean, bwd_pkt_len_mean,
                             pkt_len_mean, flow_iat_mean, down_up_ratio,
                             fin_flag, syn_flag, rst_flag, psh_flag, ack_flag]])

    # 2. Classifier Features (11 features - NO PORT ALLOWED)
    rf_features = np.array([[protocol, fwd_pkt_len_mean, bwd_pkt_len_mean,
                             pkt_len_mean, flow_iat_mean, down_up_ratio,
                             fin_flag, syn_flag, rst_flag, psh_flag, ack_flag]])

    # STAGE 1
    score = guard.get_anomaly_score(ae_features)

    # STAGE 2
    if score > guard.threshold:
        prediction = classifier.predict(rf_features)[0]

        if prediction == "Benign":
            # AI saw a weird port/shape, but verified it's just human activity
            print(f"🟢 NORMAL (Verified) | Score: {score:.4f} | Port: {flow['dport']} | Pkts: {total_pkts}")
        else:
            print(f"🚨 THREAT: {prediction.upper()}! | Score: {score:.4f} | Port: {flow['dport']} | Pkts: {total_pkts}")
    else:
        print(f"🟢 NORMAL | Score: {score:.4f} | Port: {flow['dport']} | Pkts: {total_pkts}")


print("Monitoring started. Awaiting traffic...")
sniff(prn=monitor_traffic, store=0)