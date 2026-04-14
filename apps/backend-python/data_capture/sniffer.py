import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from data_capture.threat_manager import ThreatManager
from collections import deque
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from ai_model.cyber_ai import CyberAI
from scapy.all import sniff
import time

# Setup AI
guard = CyberAI(input_dim=12) # Ensure we specify 12 features
guard.load()
print(f"AI Guard Active. Alert threshold is: {guard.threshold:.6f}")

# Global Variables
BUFFER_SIZE = 50
score_buffer = deque(maxlen=BUFFER_SIZE)
threat_manager = ThreatManager()

active_flows = {}
FLOW_TIMEOUT = 30
PACKET_LIMIT = 50 # Lowered slightly for faster real-time detection

def monitor_traffic(packet):
    if packet.haslayer(IP):
        now = time.time()

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet.proto
        sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
        dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)

        # Create direction-aware keys
        forward_key = (src_ip, dst_ip, sport, dport, proto)
        backward_key = (dst_ip, src_ip, dport, sport, proto)

        if forward_key in active_flows:
            flow_key = forward_key
            is_forward = True
        elif backward_key in active_flows:
            flow_key = backward_key
            is_forward = False
        else:
            flow_key = forward_key
            is_forward = True
            active_flows[flow_key] = {
                'start_time': now,
                'last_time': now,
                'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0,
                'flags': "",
                'dport': dport,
                'proto': proto
            }

        flow = active_flows[flow_key]
        pkt_len = len(packet)

        # Update flow metrics based on direction
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

        # End flow if it hits limits or connection closes
        if total_pkts >= PACKET_LIMIT or is_connection_done:
            predict_flow_threat(flow_key)
            del active_flows[flow_key]

def predict_flow_threat(key):
    flow = active_flows[key]

    # Calculate CIC-IDS-2018 style metrics
    fwd_pkts = max(1, flow['fwd_pkts'])
    bwd_pkts = max(1, flow['bwd_pkts'])
    total_pkts = fwd_pkts + bwd_pkts

    # Duration in seconds
    duration = max(flow['last_time'] - flow['start_time'], 0.0001)

    # 1. Dst Port (Log scaled)
    dest_port = np.log1p(flow['dport'])

    # 2. Protocol
    protocol = flow['proto']

    # 3. Fwd Pkt Len Mean
    fwd_pkt_len_mean = np.log1p(flow['fwd_bytes'] / fwd_pkts)

    # 4. Bwd Pkt Len Mean
    bwd_pkt_len_mean = np.log1p(flow['bwd_bytes'] / bwd_pkts)

    # 5. Pkt Len Mean
    pkt_len_mean = np.log1p((flow['fwd_bytes'] + flow['bwd_bytes']) / total_pkts)

    # 6. Flow IAT Mean (Time between packets in Microseconds to match CIC-IDS)
    iat_mean_seconds = duration / max(1, (total_pkts - 1))
    flow_iat_mean = np.log1p(iat_mean_seconds * 1_000_000)

    # 7. Down/Up Ratio
    down_up_ratio = flow['bwd_bytes'] / max(1, flow['fwd_bytes'])

    # 8-12. Flags (0 or 1)
    fin_flag = 1 if 'F' in flow['flags'] else 0
    syn_flag = 1 if 'S' in flow['flags'] else 0
    rst_flag = 1 if 'R' in flow['flags'] else 0
    psh_flag = 1 if 'P' in flow['flags'] else 0
    ack_flag = 1 if 'A' in flow['flags'] else 0

    features = np.array([[dest_port, protocol, fwd_pkt_len_mean, bwd_pkt_len_mean,
                          pkt_len_mean, flow_iat_mean, down_up_ratio,
                          fin_flag, syn_flag, rst_flag, psh_flag, ack_flag]])

    # Get Anomaly Score
    score = guard.get_anomaly_score(features)

    # Print logic for real-time monitoring
    status = "🔴 ANOMALY" if score > guard.threshold else "🟢 NORMAL"
    print(f"{status} | Score: {score:.6f} | Port: {flow['dport']} | Pkts: {total_pkts}")

    # (You can pass this to score_buffer and _alert_monitor later)

print("Monitoring started. Generating live network shape metrics...")
sniff(prn=monitor_traffic, store=0)