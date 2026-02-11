import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collections import deque
import numpy as np
from scapy.layers.inet import IP, TCP, UDP
from ai_model.cyber_ai import CyberAI
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

# Key: IP Address | Value: {count, total_bytes, start_time}
flow_memory = {}

def monitor_traffic(packet):
    """
    Monitors the traffic by checking each packet's data.
    :param packet: incoming packet that will be read using 'sniff'
    :return: packet details object that will be passed in to ASP.NET
    """

    global last_packet_time
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # Updating flow in memory
        now = time.time()
        if src_ip not in flow_memory:
            flow_memory[src_ip] = {'count': 1, 'bytes': len(packet), 'start': now}
        else:
            flow_memory[src_ip]['count'] += 1
            flow_memory[src_ip]['bytes'] += len(packet)

        if flow_memory[src_ip]['count'] > 100:
            flow_memory[src_ip] = {'count': 1, 'bytes': len(packet), 'start': now}

        # Calculates the bytes per second and difference between incoming and outgoing packets
        ip_stats = flow_memory[src_ip]
        duration = max(now - ip_stats['start'], 0.001)

        bps = np.log1p(ip_stats['bytes'] / duration)
        avg_pkt_size = ip_stats['bytes'] / ip_stats['count']
        pkts_diff = ip_stats['count']

        # Port
        if packet.haslayer(TCP):
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            port = packet[UDP].dport
        else:
            port = 0
        log_port =np.log1p(port)

        # Packet size
        log_size = np.log1p(len(packet))

        # Payload Ratio
        total_size = len(packet)
        if packet.haslayer(TCP):
            payload_size = len(packet[TCP].payload)
        elif packet.haslayer(UDP):
            payload_size = len(packet[UDP].payload)
        else:
            payload_size = 0
        payload_ratio = payload_size / total_size if total_size > 0 else 0

        # Delta time between consecutive packets
        now = time.time()
        packet_timestamps.append(now)
        raw_delta = now - last_packet_time
        last_packet_time = now
        delta_clipped = min(raw_delta, 5.0)
        log_delta = np.log1p(delta_clipped)

        # Time to live
        ttl = packet[IP].ttl

        # TCP Flags
        is_syn = is_ack = is_rst = is_fin = window = payload = 0
        if packet.haslayer(TCP):
            flags = str(packet[TCP].flags)
            is_syn = 1 if "S" in flags else 0
            is_ack = 1 if "A" in flags else 0
            is_rst = 1 if "R" in flags else 0
            is_fin = 1 if "F" in flags else 0
            window = np.log1p(packet[TCP].window)
            payload = np.log1p(len(packet[TCP].payload))



        # AI PREDICTION
        features = np.array([[log_port, log_size, log_delta, is_syn, is_ack, is_rst, is_fin, ttl, window, payload, payload_ratio, bps, pkts_diff, avg_pkt_size]])
        anomaly_score = guard.get_anomaly_score(features)
        score_buffer.append(anomaly_score)

        if len(flow_memory) > 1000: flow_memory.clear()

        # ALERT LOGIC
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