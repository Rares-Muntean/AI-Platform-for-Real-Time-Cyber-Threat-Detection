import numpy as np
from scapy.layers.inet import IP, TCP
from model_logic import CyberAI
from scapy.all import sniff
import time


guard = CyberAI(input_dim=4)
guard.load()
print(f"AI Guard Active. Alert threshold is: {guard.threshold}")

last_packet_time = time.time()
score_buffer = []
BUFFER_SIZE = 10

def monitor_traffic(packet):
    global last_packet_time
    if packet.haslayer(IP):
        proto = packet.proto
        size = len(packet)
        now = time.time()
        delta = now - last_packet_time
        last_packet_time = now
        flags = int(packet[TCP].flags) if packet.haslayer(TCP) else 0

        current_features = np.array([[proto, size, delta, flags]])

        anomaly_score = guard.get_anomaly_score(current_features)

        score_buffer.append(anomaly_score)

        if len(score_buffer) >= BUFFER_SIZE:
            avg_score = sum(score_buffer) / len(score_buffer)

            if avg_score > guard.threshold:
                print(f"🔥 [BATCH ALERT] Average Score: {avg_score:.4f} | Status: SUSPICIOUS")
            else:
                print(f"Batch Safe: {avg_score:.4f}")
                pass


print("Monitoring started. Try to browse the web or run a test...")
sniff(prn=monitor_traffic, store=0)