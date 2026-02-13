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
guard = CyberAI()
guard.load()
print(f"AI Guard Active. Alert threshold is: {guard.threshold}")

# Global Variables
BUFFER_SIZE = 50
last_packet_time = time.time()
packet_timestamps = deque(maxlen=1000)
score_buffer = deque(maxlen=BUFFER_SIZE)

threat_manager = ThreatManager()

# Key: src_ip, dst_ip, src_port, dst_port, proto
active_flows = {}
FLOW_TIMEOUT = 30
PACKET_LIMIT = 100

def monitor_traffic(packet):
    """
    Monitors the traffic by checking flow of packets.
    :param packet: incoming packet that will be read using 'sniff'
    :return: packet details object that will be passed in to ASP.NET
    """
    if packet.haslayer(IP):
        now = time.time()

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet.proto
        sport = packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else 0)
        dport = packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else 0)

        flow_key = (src_ip, dst_ip, sport, dport, proto)

        if flow_key not in active_flows:
            active_flows[flow_key] = {
                'start_time': now,
                'last_time': now,
                'packet_count': 1,
                'byte_count': len(packet),
                'flags': str(packet[TCP].flags) if packet.haslayer(TCP) else "",
                'ttl_sum': packet[IP].ttl,
                'win_sum': packet[TCP].window if packet.haslayer(TCP) else 0,
                'payload_sum': len(packet[TCP].payload) if packet.haslayer(TCP) else 0,
                'max_pkt_size': len(packet),
            }

        else:
            flow = active_flows[flow_key]
            flow['packet_count'] += 1
            flow['byte_count'] += len(packet)
            flow['last_time'] = now
            flow['ttl_sum'] += packet[IP].ttl
            if packet.haslayer(TCP):
                flow['flags'] += str(packet[TCP].flags)
                flow['win_sum'] += packet[TCP].window
                flow['payload_sum'] += len(packet[TCP].payload)
            if len(packet) > active_flows[flow_key]['max_pkt_size']:
                active_flows[flow_key]['max_pkt_size'] = len(packet)

        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            is_connection_done = 'F' in str(tcp_flags) or 'R' in str(tcp_flags)
        else:
            is_connection_done = False

        if active_flows[flow_key]['packet_count'] >= PACKET_LIMIT or is_connection_done:
            predict_flow_threat(flow_key)
            del active_flows[flow_key]

def predict_flow_threat(key):
    flow = active_flows[key]
    duration = max(flow['last_time'] - flow['start_time'], 0.0001)

    # --- Getting features from the ended flow ---
    #   (0: src_ip, 1: dst_ip, 2: source port, 3: dest port, 4: proto)
    # Port
    log_port = np.log1p(key[3])

    # MAX Packet Size
    log_size = np.log1p(flow['max_pkt_size'])

    # Time Delta (Represents flow duration)
    log_duration = np.log1p(duration)

    # Flags
    is_syn = 1 if 'S' in flow['flags'] else 0
    is_ack = 1 if 'A' in flow['flags'] else 0
    is_fin = 1 if 'F' in flow['flags'] else 0
    is_rst = 1 if 'R' in flow['flags'] else 0

    # Avg ttl and window
    avg_ttl = flow['ttl_sum'] / flow['packet_count']
    avg_window = flow['win_sum'] / flow['packet_count']
    log_window = np.log1p(avg_window)

    # Payload Ratio
    avg_payload = flow['payload_sum'] / flow['packet_count']
    log_payload = np.log1p(avg_payload)
    payload_ratio = flow['payload_sum'] / flow['byte_count'] if flow['byte_count'] > 0 else 0

    # Bytes Per Second
    bps = np.log1p(flow['byte_count'] / duration)

    # Packets Count
    pkts_count = flow['packet_count']

    # Avg packet size
    avg_pkt_size = flow['byte_count'] / flow['packet_count']


    features = np.array([[log_port, log_size, log_duration, is_syn, is_ack, is_rst, is_fin, avg_ttl, log_window,
                          log_payload, payload_ratio, bps, pkts_count, avg_pkt_size]])

    score = guard.get_anomaly_score(features)

    print(score)

def _alert_monitor():
    """
    Alerts the backend when the AI model detected an anomaly during sniffing. Checks in batches of x packets the ones
    that have anomaly score above a certain threshold. Those certain packets will be passed in to the 'threat_manager'
    class to identify if the attacks are distributed / single threats.
    :return:
    """
    if len(score_buffer) == BUFFER_SIZE:
        scores_array = np.array([item['score'] for item in score_buffer])
        avg_score = np.mean(scores_array)
        std_dev = np.std(scores_array)

        # Debug only (not for production, delete later)
        if avg_score < 0.10:
            if np.random.random() < 0.02:
                print(f"SAFE | {avg_score:.4f}")
            return

        # Checks each individual packet for the most suspicious scores.
        suspicious_entries = [item for item in score_buffer if item['score'] > 0.08]
        unique_ips_in_batch = set(item['info']['src'] for item in suspicious_entries)

        peak_packet = max(score_buffer, key=lambda x: x['score'])

        threat_type = "SINGLE_SOURCE"
        attackers_count = 1

        for ip in unique_ips_in_batch:
            t_type, t_port, t_count = threat_manager.process_finding(ip, peak_packet['info']['port'], avg_score)
            if t_type == "DISTRIBUTED_ATTACK":
                threat_type = "DISTRIBUTED_ATTACK"
                attackers_count = t_count

        severity = "CRITICAL" if (avg_score > 0.12 and std_dev < 0.005) or threat_type == "DISTRIBUTED ATTACK" else "WARNING"

        if threat_manager.is_allowed_to_send(peak_packet['info']['src'], threat_type):
            # Fill later with data that will be sent to backend aspnet
            payload = {}
            # TO BE IMPLEMENTED:  _send_to_backend()
            print(f"{severity} [{threat_type}] Alert Sent!")





print("Monitoring started. System is learning to ignore background noise...")
sniff(prn=monitor_traffic, store=0)