from collections import deque, Counter
import time

from torch import unique


class ThreatManager:
    def __init__(self):
        self.ip_cooldowns = {}
        self.last_web_alert_time = 0
        self.recent_ips = deque(maxlen=100)

    def process_finding(self, src_ip, port, score):
        self.recent_ips.append(src_ip)

        unique_attackers = len(set(self.recent_ips))

        if unique_attackers > 5:
            return "DISTRIBUTED_ATTACK", port, unique_attackers

        return "SINGLE_SOURCE", port, 1

    def is_allowed_to_send(self, src_ip, threat_type):
        now = time.time()

        if threat_type == "DISTRIBUTED_ATTACK":
            if now - self.last_web_alert_time > 30:
                self.last_web_alert_time = now
                return True

        else:
            if src_ip not in self.ip_cooldowns or (now - self.ip_cooldowns[src_ip] > 60):
                self.ip_cooldowns[src_ip] = now
                return True

        return False
