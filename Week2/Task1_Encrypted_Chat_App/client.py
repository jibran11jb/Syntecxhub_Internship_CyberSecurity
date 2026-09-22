"""
Encrypted Chat App - Client
Project 1: Client/server chat with AES encryption over TCP.

Run:  python client.py
"""

import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "127.0.0.1"   # change to server IP if connecting remotely
PORT = 5555

# Must match the server's key exactly (pre-shared key)
PSK = b"0123456789abcdef0123456789abcdef"  # 32 bytes
aesgcm = AESGCM(PSK)


def encrypt(plaintext: str) -> bytes:
    nonce = os.urandom(12)  # new random nonce every message
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce + ct


def decrypt(data: bytes) -> str:
    nonce, ct = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def listen_for_messages(sock):
    while True:
        length_bytes = recv_exact(sock, 4)
        if not length_bytes:
            print("\n[!] Disconnected from server")
            os._exit(0)
        msg_len = int.from_bytes(length_bytes, "big")
        data = recv_exact(sock, msg_len)
        if not data:
            break
        try:
            print(f"\n[peer]: {decrypt(data)}\nYou: ", end="", flush=True)
        except Exception:
            print("\n[!] Failed to decrypt incoming message")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")

    threading.Thread(target=listen_for_messages, args=(sock,), daemon=True).start()

    while True:
        text = input("You: ")
        if text.lower() in ("exit", "quit"):
            break
        data = encrypt(text)
        sock.sendall(len(data).to_bytes(4, "big") + data)

    sock.close()


if __name__ == "__main__":
    main()
