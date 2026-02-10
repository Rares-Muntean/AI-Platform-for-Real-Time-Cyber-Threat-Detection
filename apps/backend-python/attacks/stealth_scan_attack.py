import socket
import time

target_ip = "192.168.1.143"
ports = [21, 22, 23, 25, 53, 80, 110, 135, 443, 445, 3306, 3389]

print(f"--- Starting Stealth Scan on {target_ip} ---")

for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.1)
    result = s.connect_ex((target_ip, port))
    if result == 0:
        print(f"Port {port}: OPEN")
    s.close()
    time.sleep(0.5)

print("Scan Complete.")