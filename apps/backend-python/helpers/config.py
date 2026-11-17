import json
import os

HELPERS_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HELPERS_DIR, "agent_config.json")

DEFAULT_CONFIG = {
    "interface": None, # "enp0s3", "tun0", "wg0", null
    "capture_mode": "scapy",  # "scapy" or "nfqueue"
    "firewall_enabled": True,
    "block_duration_seconds": 60,
    "control_port": 5005,
    "protect_management_ports": True,  # SSH (22) & Backend (5284) open when testing from same PC
    "whitelist_ips": ["127.0.0.1"],
    "device_ip_override": None,
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_PATH, "r") as f:
            data = json.load(f)

        merged = DEFAULT_CONFIG.copy()
        merged.update(data)
        return merged
    except Exception as e:
        print(f"[CONFIG ERROR] Failed to load agent_config.json, using defaults: {e}")
        return DEFAULT_CONFIG.copy()


def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=4)