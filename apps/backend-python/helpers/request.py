import datetime
import time
from datetime import datetime,timezone
import requests
import os
import json

########## BACKEND CONFIG ##########
dir_path = os.path.dirname(os.path.realpath(__file__))
config_path = os.path.join(dir_path, "ip_config.txt")

backend_ip = "192.168.1.226"

if os.path.exists(config_path):
    try:
        with open(config_path, "r") as f:
            backend_ip = f.read().strip()
            print(f"[CONFIG] Loaded dynamic backend IP: {backend_ip}")
    except Exception as e:
        print(f"[CONFIG ERROR] Failed to read ip_config.txt: {e}")
else:
    print(f"[CONFIG] No ip_config.txt found. Using fallback IP: {backend_ip}")

API_BASE = f"http://{backend_ip}:5284/api/alerts/add"
COOLDOWN_SECONDS = 60
####################################

def report_threat_to_backend(flow, total_pkts, score, alert_cooldowns):
    attacker_ip = flow["src_ip"]
    now = time.time()

    if attacker_ip in alert_cooldowns:
        time_since_last_alert = now - alert_cooldowns[attacker_ip]
        if time_since_last_alert < COOLDOWN_SECONDS:
            return

    alert_cooldowns[attacker_ip] = now

    payload = {
        "sourceIp": attacker_ip,
        "destinationIp": flow["dst_ip"],
        "destinationPort": int(flow["dport"]),
        "protocol": int(flow["proto"]),
        "anomalyScore": float(score),
        "totalPackets": float(total_pkts),
        "timeStamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') 
    }

    try:
        response = requests.post(API_BASE, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"[API] Succesfully sent alert for {attacker_ip} to backend")
    except Exception as e:
        print(f"[API ERROR] Could not reach C# backend: {e}")