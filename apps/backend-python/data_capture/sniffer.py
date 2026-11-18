import os
import sys
import threading
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from ai_model.cyber_ai import CyberAI
from helpers.config import load_config
from helpers.firewall import FirewallManager
from helpers.request import report_threat_to_backend

cfg = load_config()
alert_cooldowns = {}

guard = CyberAI(input_dim=13)
guard.load()

firewall = FirewallManager(
    enabled=cfg["firewall_enabled"],
    block_duration=cfg["block_duration_seconds"],
    whitelist_ips=cfg["whitelist_ips"],
    protect_mgmt_ports=cfg["protect_management_ports"],
)
firewall.setup_chain()

active_flows = {}
PACKET_LIMIT = 50


def monitor_traffic(packet):
    if packet.haslayer(IP):
        now = time.time()

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet.proto
        sport = (
        packet[TCP].sport
        if packet.haslayer(TCP)
        else (packet[UDP].sport if packet.haslayer(UDP) else 0)
    )
        dport = (
            packet[TCP].dport
            if packet.haslayer(TCP)
            else (packet[UDP].dport if packet.haslayer(UDP) else 0)
        )

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
              "start_time": now,
              "last_time": now,
              "fwd_pkts": 0,
              "bwd_pkts": 0,
              "fwd_bytes": 0,
              "bwd_bytes": 0,
              "flags": "",
              "dport": actual_dport,
              "proto": proto,
              "src_ip": forward_key[0],
              "dst_ip": forward_key[1],
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

        if total_pkts >= PACKET_LIMIT or is_connection_done:
            is_anomaly = predict_flow_threat(flow_key)
            del active_flows[flow_key]
            return is_anomaly

        return False


def predict_flow_threat(key):
    flow = active_flows[key]

    fwd_pkts = max(1, flow['fwd_pkts'])
    bwd_pkts = max(1, flow['bwd_pkts'])
    total_pkts = fwd_pkts + bwd_pkts
    duration = max(flow['last_time'] - flow['start_time'], 0.0001)

    dest_port = np.log1p(flow['dport'])
    is_privileged_port = 1 if flow['dport'] < 1024 else 0
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

    ae_features = np.array([[
      dest_port,
      is_privileged_port,
      protocol,
      fwd_pkt_len_mean,
      bwd_pkt_len_mean,
      pkt_len_mean,
      flow_iat_mean,
      down_up_ratio,
      fin_flag,
      syn_flag,
      rst_flag,
      psh_flag,
      ack_flag,
    ]])

    score, error_vector = guard.get_anomaly_score(ae_features)
    total_pkts = flow["fwd_pkts"] + flow["bwd_pkts"]

    if score > guard.threshold:
        print(
            f"[!!!] ANOMALY DETECTED | Src: {flow['src_ip']} | Score: {score:.4f} |"
            f" Port: {flow['dport']} | Pkts: {total_pkts}"
        )
        blocked = firewall.block_ip(flow["src_ip"])
        flow_copy = flow.copy()
        threading.Thread(
            target=report_threat_to_backend,
            args=(flow_copy, total_pkts, score, alert_cooldowns),
            kwargs={
                "device_ip_override": cfg["device_ip_override"],
                "blocked": blocked
            },
            daemon=True
        ).start()
        return True
    else:
        print(
            f"[OK] Normal Traffic  | Src: {flow['src_ip']} | Score: {score:.4f} |"
            f" Port: {flow['dport']} | Pkts: {total_pkts}"
        )
        return False

def run_nfqueue_mode(iface):
    from netfilterqueue import NetfilterQueue
    firewall.setup_nfqueue(queue_num=1, interface=iface)
    nfq = NetfilterQueue()

    def on_packet(pkt):
        try:
          scapy_pkt = IP(pkt.get_payload())
          if monitor_traffic(scapy_pkt):
            pkt.drop()
          else:
            pkt.accept()
        except Exception as e:
          print(f"[NFQUEUE ERROR] {e}")
          pkt.accept()

    nfq.bind(1, on_packet)
    try:
        nfq.run()
    finally:
        nfq.unbind()



if __name__ == "__main__":
    iface = cfg["interface"]
    mode = cfg["capture_mode"].lower()
    bpf_filter = (
      f"ip and not port 5284 and not port {cfg['control_port']}"
    )
    print("=================================================")
    print("VELOX Agent Started")
    print(f"Interface      : {iface if iface else 'ALL / Default'}")
    print(f"Firewall       : {'ENABLED' if cfg['firewall_enabled'] else 'DISABLED'}")
    print(f"Threshold      : {guard.threshold:.6f}")
    print("=================================================")

    try:
        if mode == "nfqueue":
            run_nfqueue_mode(iface)
        else:
            sniff_kwargs = {"prn": monitor_traffic, "store": 0, "filter": bpf_filter}
            if iface:
                sniff_kwargs["iface"] = iface
            sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\nShutting down VELOX Agent...")
    finally:
        firewall.cleanup()