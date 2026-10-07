import subprocess
import time
import os
import signal
import socket
import sys

print("[PYTHON] Starting QEMU with port forwarding 8080 -> 8080...")
home = os.environ['HOME']
qemu_cmd = [
    "qemu-system-x86_64",
    "-M", "q35",
    "-m", "512M",
    "-drive", f"if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd",
    "-drive", f"if=pflash,format=raw,file={home}/nexus-os/OVMF_VARS.local.fd",
    "-cdrom", f"{home}/nexus-os/nexus.iso",
    "-device", "nvme,drive=nvmedrive,serial=deadbeef",
    "-drive", f"if=none,id=nvmedrive,format=raw,file={home}/nexus-os/nvme-test.img",
    "-netdev", "user,id=net0,hostfwd=tcp::8080-:8080",
    "-device", "virtio-net-pci,netdev=net0",
    "-nographic",
    "-no-reboot",
    "-no-shutdown"
]

qemu = subprocess.Popen(qemu_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

# Read output until prompt
output_log = ""
prompt_found = False
for _ in range(200000):
    char = qemu.stdout.read(1)
    if not char: break
    try:
        decoded = char.decode('utf-8', errors='ignore')
        output_log += decoded
        print(decoded, end='', flush=True)
        if "Nexus>" in output_log:
            prompt_found = True
            break
    except:
        pass

if not prompt_found:
    print("[PYTHON] FAIL: Did not reach Nexus prompt")
    qemu.send_signal(signal.SIGTERM)
    sys.exit(1)

print("\n[PYTHON] Sending 'spawn tcpserver'...")
qemu.stdin.write(b"spawn tcpserver\n")
qemu.stdin.flush()

# Wait for server to start listening
server_listening = False
start_wait = time.time()
while time.time() - start_wait < 10:
    char = qemu.stdout.read(1)
    if not char: break
    decoded = char.decode('utf-8', errors='ignore')
    output_log += decoded
    print(decoded, end='', flush=True)
    if "listening on 0.0.0.0:8080" in output_log:
        server_listening = True
        break

if not server_listening:
    print("[PYTHON] FAIL: tcpserver did not start listening in time")
    qemu.send_signal(signal.SIGTERM)
    sys.exit(1)

# Connect from Python client to port 8080
print("\n[PYTHON] Connecting to 127.0.0.1:8080...")
response_data = b""
client_success = False

time.sleep(0.5)

for attempt in range(5):
    try:
        s = socket.create_connection(('127.0.0.1', 8080), timeout=5)
        print(f"[PYTHON] Connected on attempt {attempt+1}!")
        request = b"GET /hello HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
        print("[PYTHON] Sending HTTP request...")
        s.sendall(request)
        
        # Read response
        while True:
            chunk = s.recv(1024)
            if not chunk: break
            response_data += chunk
            
        s.close()
        client_success = True
        break
    except Exception as e:
        print(f"[PYTHON] Connection attempt {attempt+1} failed: {e}")
        time.sleep(0.5)

print(f"\n[PYTHON] Client received response ({len(response_data)} bytes):")
print(response_data.decode('utf-8', errors='ignore'))

# Read remaining serial output to observe accept, PASS, and reap
start_drain = time.time()
while time.time() - start_drain < 10:
    char = qemu.stdout.read(1)
    if not char: break
    decoded = char.decode('utf-8', errors='ignore')
    output_log += decoded
    print(decoded, end='', flush=True)
    if "reaped pid=" in output_log:
        break

# Verification
print("\n[PYTHON] Terminating QEMU...")
qemu.send_signal(signal.SIGTERM)

assert client_success, "Failed to connect to tcpserver"
assert b"HTTP/1.0 200 OK" in response_data, "Response missing HTTP 200 OK"
assert b"Hello from Noxisa TCP Server!" in response_data, "Response missing expected body"
assert "tcpserver: PASS" in output_log, "Serial log missing 'tcpserver: PASS'"
assert "reaped pid=" in output_log, "Serial log missing reap confirmation"

print("\n[PYTHON] ALL CHECKS PASSED: TCP SERVER VERIFIED END-TO-END!")

