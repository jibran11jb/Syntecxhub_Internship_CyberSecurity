"""
Encrypted Chat App - Server
Project 1: Client/server chat with AES encryption over TCP.

Run:  python server.py
"""

import socket
import threading
import os
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "0.0.0.0"
PORT = 5555

# --- Pre-shared key (32 bytes = AES-256) ---
# In real use, exchange this securely out-of-band. Here it's a fixed
# pre-shared key so client and server can encrypt/decrypt to each other.
PSK = b"0123456789abcdef0123456789abcdef"  # 32 bytes

aesgcm = AESGCM(PSK)

clients = []          # list of connected client sockets
clients_lock = threading.Lock()
LOG_FILE = "chat_log.txt"


def log_message(text):
    """Append a message to the log file with a timestamp."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")


def encrypt(plaintext: str) -> bytes:
    """AES-GCM encrypt. A fresh random 12-byte nonce is generated
    every time (safe IV usage) and sent along with the ciphertext."""
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ct  # prepend nonce so receiver can decrypt


def decrypt(data: bytes) -> str:
    nonce, ct = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()


def broadcast(data: bytes, sender_socket):
    """Send encrypted data to every other connected client."""
    with clients_lock:
        for c in clients:
            if c is not sender_socket:
                try:
                    c.sendall(len(data).to_bytes(4, "big") + data)
                except OSError:
                    pass


def recv_exact(sock, n):
    """Read exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def handle_client(conn, addr):
    print(f"[+] {addr} connected")
    with clients_lock:
        clients.append(conn)

    try:
        while True:
            length_bytes = recv_exact(conn, 4)
            if not length_bytes:
                break
            msg_len = int.from_bytes(length_bytes, "big")
            data = recv_exact(conn, msg_len)
            if not data:
                break

            plaintext = decrypt(data)
            print(f"[{addr}] {plaintext}")
            log_message(f"{addr} -> {plaintext}")

            broadcast(data, conn)  # relay ciphertext to other clients
    except Exception as e:
        print(f"[!] Error with {addr}: {e}")
    finally:
        with clients_lock:
            if conn in clients:
                clients.remove(conn)
        conn.close()
        print(f"[-] {addr} disconnected")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
