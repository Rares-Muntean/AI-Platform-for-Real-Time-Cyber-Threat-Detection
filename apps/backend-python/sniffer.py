from collections import deque
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from model_logic import CyberAI
from scapy.all import sniff
import time

# 1. Setup AI
guard = CyberAI()
guard.load()
print(f"AI Guard Active. Alert threshold is: {guard.threshold}")

last_packet_time = time.time()
packet_timestamps = deque(maxlen=1000)
score_buffer = deque(maxlen=50)
BUFFER_SIZE = 50


def monitor_traffic(packet):
    global last_packet_time

    if packet.haslayer(IP):
        # --- FEATURE EXTRACTION ---
        if packet.haslayer(TCP):
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
        else:
            port = 0
        log_port =np.log1p(port)

        log_size = np.log1p(len(packet))

        # Calculate Payload Ratio
        total_size = len(packet)
        if packet.haslayer(TCP):
            payload_size = len(packet[TCP].payload)
        elif packet.haslayer(UDP):
            payload_size = len(packet[UDP].payload)
        else:
            payload_size = 0

        payload_ratio = payload_size / total_size if total_size > 0 else 0

        # Detla Time
        now = time.time()
        packet_timestamps.append(now)
        raw_delta = now - last_packet_time
        last_packet_time = now
        delta_clipped = min(raw_delta, 5.0)
        log_delta = np.log1p(delta_clipped)

        pps = len(packet_timestamps) / (now - packet_timestamps[0]) if len(packet_timestamps) > 1 else 0



        ttl = packet[IP].ttl

        is_syn = is_ack = is_rst = is_fin = window = payload = 0
        if packet.haslayer(TCP):
            flags = str(packet[TCP].flags)
            is_syn = 1 if "S" in flags else 0
            is_ack = 1 if "A" in flags else 0
            is_rst = 1 if "R" in flags else 0
            is_fin = 1 if "F" in flags else 0
            window = np.log1p(packet[TCP].window)
            payload = np.log1p(len(packet[TCP].payload))

        # --- AI PREDICTION ---
        features = np.array([[log_port, log_size, log_delta, is_syn, is_ack, is_rst, is_fin, ttl, window, payload, payload_ratio]])
        anomaly_score = guard.get_anomaly_score(features)

        score_buffer.append(anomaly_score)

        # --- ALERT LOGIC ---
        if len(score_buffer) == BUFFER_SIZE:
            scores_array = np.array(score_buffer)
            avg_score = np.mean(scores_array)
            std_dev = np.std(scores_array)

            if avg_score > 0.12 and std_dev < 0.005:
                status = f"🔴 CRITICAL THREAT (Robotic Flood) | Score: {avg_score:.4f}"
                print(status)

            elif avg_score > 0.10:
                status = f"🟡 HEAVY USAGE (Organic Burst) | Score: {avg_score:.4f}"
                if np.random.random() < 0.05:
                    print(status)

            else:
                if np.random.random() < 0.02:
                    print(f"🟢 SAFE | Score: {avg_score:.4f}")


print("Monitoring started. System is learning to ignore background noise...")
sniff(prn=monitor_traffic, store=0)