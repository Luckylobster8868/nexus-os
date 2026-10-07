import subprocess
import time
import os
import signal
import threading
import socket

def run_server():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', 8000))
        s.listen(1)
        print("[TCP] Server listening on port 8000")
        conn, addr = s.accept()
        print(f"[TCP] Connection from {addr}")
        data = conn.recv(1024)
        print(f"[TCP] Received:\n{data.decode('utf-8', 'ignore')}")
        conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello Noxisa!\n")
        conn.close()
        s.close()
    except Exception as e:
        print(f"[TCP] Error: {e}")

http_thread = threading.Thread(target=run_server)
http_thread.daemon = True
http_thread.start()

# Start QEMU
print("[PYTHON] Starting QEMU...")
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
    "-netdev", "user,id=net0",
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

if prompt_found:
    print("\n[PYTHON] Sending 'spawn nettest'...")
    qemu.stdin.write(b"spawn nettest\n")
    qemu.stdin.flush()
    
    # Read remaining
    start_time = time.time()
    while time.time() - start_time < 15:
        char = qemu.stdout.read(1)
        if not char: break
        decoded = char.decode('utf-8', errors='ignore')
        output_log += decoded
        print(decoded, end='', flush=True)
        if "reaped pid=" in output_log:
            break

print("\n[PYTHON] Terminating QEMU...")
qemu.send_signal(signal.SIGTERM)
