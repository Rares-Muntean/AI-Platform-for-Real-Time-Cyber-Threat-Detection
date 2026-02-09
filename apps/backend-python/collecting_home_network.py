# import pandas as pd
# import time
# import numpy as np
# from scapy.all import sniff
# from scapy.layers.inet import IP, TCP, UDP
#
# my_data = []
# last_time = time.time()
#
#
# def collect(pkt):
#     global last_time
#     if pkt.haslayer(IP):
#
#         p = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
#
#         size = np.log1p(len(pkt))
#
#         now = time.time()
#         delta = np.log1p(min(now - last_time, 10.0))
#         last_time = now
#
#         ttl = pkt[IP].ttl
#         is_syn = is_ack = is_rst = is_fin = window = payload = 0
#         if pkt.haslayer(TCP):
#             f = str(pkt[TCP].flags)
#             is_syn, is_ack, is_rst, is_fin = (1 if 'S' in f else 0), (1 if 'A' in f else 0), (1 if 'R' in f else 0), (
#                 1 if 'F' in f else 0)
#             window, payload = np.log1p(pkt[TCP].window), np.log1p(len(pkt[TCP].payload))
#
#         my_data.append([p, size, delta, is_syn, is_ack, is_rst, is_fin, ttl, window, payload])
#
#
# print("Recording your personal network DNA... (2 minutes)")
# sniff(prn=collect, timeout=240)
#
# df = pd.DataFrame(my_data,
#                   columns=["dest_port", "packet_size", "time_delta", "is_syn", "is_ack", "is_rst", "is_fin", "ttl",
#                            "tcp_window", "payload_len"])
# df.to_csv("datasets/my_home_traffic.csv", index=False)
# print("Saved!")
import pandas as pd

lab_df = pd.read_csv("datasets/better_normal_traffic.csv")
home_df = pd.read_csv("datasets/my_home_traffic.csv")
hybrid_df = pd.concat([lab_df, home_df], ignore_index=True)
hybrid_df.to_csv("datasets/hybrid_traffic.csv", index=False)