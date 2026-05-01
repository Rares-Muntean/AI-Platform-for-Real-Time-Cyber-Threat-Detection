import datetime
import time
from datetime import datetime,timezone
import requests


########## BACKEND CONFIG ##########
API_URL = "http://192.168.1.226:5284/api/alerts"
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
        "totalPackets": int(total_pkts),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"[API] Succesfully sent alert for {attacker_ip} to backend")
    except Exception as e:
        print(f"[API ERROR] Could not reach C# backend: {e}")