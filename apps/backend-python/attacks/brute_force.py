import socket
import time

target_ip = "10.167.187.237"
target_port = 22

print(f"--- Simulating SSH Brute Force on {target_ip} ---")

for i in range(50):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        s.send(b"admin:password123")
        s.close()
        print(f"Attempt {i+1} sent...")
        time.sleep(1)
    except:
        pass

print("Brute force simulation complete.")