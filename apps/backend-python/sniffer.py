from collections import deque
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from model_logic import CyberAI
from scapy.all import sniff
import time

# 1. Setup AI
guard = CyberAI(input_dim=10)
guard.load()
print(f"AI Guard Active. Alert threshold is: {guard.threshold}")

last_packet_time = time.time()
packet_timestamps = deque(maxlen=1000)
score_buffer = deque(maxlen=75)
BUFFER_SIZE = 75


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

        log_size = np.log1p(len(packet))

        now = time.time()
        packet_timestamps.append(now)
        raw_delta = now - last_packet_time
        last_packet_time = now

        if len(packet_timestamps) > 1:
            duration = now - packet_timestamps[0]
            pps = len(packet_timestamps) / duration if duration > 0.001 else 0
        else:
            pps = 0

        delta_clipped = min(raw_delta, 5.0)
        log_delta = np.log1p(delta_clipped)

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
        features = np.array([[port, log_size, log_delta, is_syn, is_ack, is_rst, is_fin, ttl, window, payload]])
        anomaly_score = guard.get_anomaly_score(features)

        # # --- STABLE MULTIPLIER ---
        # boost = 1.0
        # if pps > 800:
        #     boost = np.log10(pps)

        # anomaly_score *= boost
        score_buffer.append(anomaly_score)

        # --- ALERT LOGIC ---
        if len(score_buffer) == BUFFER_SIZE:
            avg_score = sum(score_buffer) / BUFFER_SIZE

            if avg_score > 0.30:
                status = f"🔴 CRITICAL THREAT | Score: {avg_score:.4f} | PPS: {pps:.1f}"
                print(status)
            elif avg_score > 0.12:
                status = f"🟡 UNUSUAL ACTIVITY | Score: {avg_score:.4f} | PPS: {pps:.1f}"
                print(status)
            else:
                if np.random.random() < 0.12:
                    print(f"🟢 SAFE | Score: {avg_score:.4f}")


print("Monitoring started. System is learning to ignore background noise...")
sniff(prn=monitor_traffic, store=0)