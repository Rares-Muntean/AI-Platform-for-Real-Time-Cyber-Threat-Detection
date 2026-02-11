import socket
import random

target_ip = "192.168.1.143"

print("Spamming VM with malformed requests...")
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.001)
        s.connect((target_ip, random.randint(1, 65535)))
        s.close()
    except:
        pass

