#!/usr/bin/env python3
"""Encrypted file server: TLS 1.2+ transport, HMAC-verified chunks, AES-256-GCM at rest."""
import argparse, hashlib, hmac, json, os, socket, ssl, sys, threading
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from common import *


class Store:
    """On-disk layout: <root>/<sha256(name)>/meta.json + NNNNNNNN.chunk (each chunk AES-GCM wrapped)."""

    def __init__(self, root, master_key_path):
        self.root = root
        os.makedirs(root, exist_ok=True)
        if not os.path.exists(master_key_path):
            fd = os.open(master_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(os.urandom(32))
        with open(master_key_path, "rb") as f:
            self.aes = AESGCM(f.read())
        self.lock = threading.Lock()

    def dir(self, name):
        return os.path.join(self.root, file_id(safe_name(name)))

    def meta(self, name):
        p = os.path.join(self.dir(name), "meta.json")
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)

    def _save_meta(self, name, m):
        p = os.path.join(self.dir(name), "meta.json")
        with open(p + ".tmp", "w") as f:
            json.dump(m, f)
        os.replace(p + ".tmp", p)

    def next_chunk(self, name):
        i = 0
        while os.path.exists(os.path.join(self.dir(name), f"{i:08d}.chunk")):
            i += 1
        return i

    def init(self, name, size, chunk_size, nchunks, salt):
        with self.lock:
            m = self.meta(name)
            if m and m["complete"]:
                raise ValueError("file already exists")
            if m and (m["size"], m["nchunks"], m["chunk_size"]) == (size, nchunks, chunk_size):
                return m["salt"], self.next_chunk(name)          # resume
            os.makedirs(self.dir(name), exist_ok=True)
            for f in os.listdir(self.dir(name)):                 # stale partial upload
                os.remove(os.path.join(self.dir(name), f))
            self._save_meta(name, dict(name=name, size=size, chunk_size=chunk_size, nchunks=nchunks,
                                       salt=salt, complete=False, sha256=None))
            return salt, 0

    def put_chunk(self, name, index, blob):
        if index != self.next_chunk(name):
            raise ValueError("out-of-order chunk")
        nonce = os.urandom(12)
        wrapped = nonce + self.aes.encrypt(nonce, blob, f"{file_id(name)}|{index}".encode())
        p = os.path.join(self.dir(name), f"{index:08d}.chunk")
        with open(p + ".tmp", "wb") as f:
            f.write(wrapped)
        os.replace(p + ".tmp", p)

    def get_chunk(self, name, index):
        with open(os.path.join(self.dir(name), f"{index:08d}.chunk"), "rb") as f:
            w = f.read()
        return self.aes.decrypt(w[:12], w[12:], f"{file_id(name)}|{index}".encode())   # InvalidTag if tampered

    def complete(self, name, sha):
        with self.lock:
            m = self.meta(name)
            if not m or self.next_chunk(name) != m["nchunks"]:
                raise ValueError("upload incomplete")
            m.update(complete=True, sha256=sha)
            self._save_meta(name, m)

    def list(self):
        out = []
        for d in os.listdir(self.root):
            p = os.path.join(self.root, d, "meta.json")
            if os.path.exists(p):
                m = json.load(open(p))
                out.append(dict(name=m["name"], size=m["size"], complete=m["complete"]))
        return out


def handle(conn, store, mac_key):
    try:
        challenge = os.urandom(16)
        send_json(conn, {"challenge": challenge.hex()})
        proof = recv_json(conn).get("proof", "")
        if not hmac.compare_digest(proof, hmac.new(mac_key, b"hello" + challenge, hashlib.sha256).hexdigest()):
            send_json(conn, {"ok": False, "error": "authentication failed"})
            return
        send_json(conn, {"ok": True})
        while True:
            msg = recv_json(conn)
            cmd = msg.get("cmd")
            try:
                if cmd == "INIT":
                    name = safe_name(msg["name"])
                    salt, nxt = store.init(name, int(msg["size"]), int(msg["chunk_size"]),
                                           int(msg["nchunks"]), msg["salt"])
                    send_json(conn, {"ok": True, "salt": salt, "next_chunk": nxt})
                elif cmd == "CHUNK":
                    name, idx = safe_name(msg["name"]), int(msg["index"])
                    blob, mac = recv_frame(conn), recv_frame(conn)
                    if not hmac.compare_digest(mac, chunk_mac(mac_key, file_id(name), idx, blob)):
                        send_json(conn, {"ok": False, "error": "HMAC mismatch"})
                        continue
                    store.put_chunk(name, idx, blob)
                    send_json(conn, {"ok": True})
                elif cmd == "COMPLETE":
                    store.complete(safe_name(msg["name"]), msg["sha256"])
                    send_json(conn, {"ok": True})
                elif cmd == "DOWNLOAD":
                    name = safe_name(msg["name"])
                    m = store.meta(name)
                    if not m or not m["complete"]:
                        send_json(conn, {"ok": False, "error": "not found"})
                        continue
                    send_json(conn, {"ok": True, **{k: m[k] for k in ("size", "chunk_size", "nchunks", "salt", "sha256")}})
                    for i in range(m["nchunks"]):
                        try:
                            blob = store.get_chunk(name, i)
                        except (InvalidTag, OSError):
                            send_frame(conn, ERR_MARK)                 # storage integrity failure
                            return
                        send_frame(conn, blob)
                        send_frame(conn, chunk_mac(mac_key, file_id(name), i, blob))
                elif cmd == "LIST":
                    send_json(conn, {"ok": True, "files": store.list()})
                else:
                    send_json(conn, {"ok": False, "error": "unknown command"})
            except (ValueError, KeyError) as e:
                send_json(conn, {"ok": False, "error": str(e)})
    except (ConnectionError, OSError, ssl.SSLError, json.JSONDecodeError):
        pass
    finally:
        conn.close()


class Server:
    def __init__(self, host, port, certfile, keyfile, storage, token, master_key=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.load_cert_chain(certfile, keyfile)
        self.mac_key = derive_mac_key(token)
        self.store = Store(storage, master_key or os.path.join(storage, "..", "master.key"))
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(16)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def serve_forever(self):
        while not self._stop:
            try:
                raw, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._client, args=(raw,), daemon=True).start()

    def _client(self, raw):
        try:
            raw.settimeout(60)
            conn = self.ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        handle(conn, self.store, self.mac_key)

    def stop(self):
        self._stop = True
        self.sock.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--cert", default="certs/server.crt")
    ap.add_argument("--key", default="certs/server.key")
    ap.add_argument("--storage", default="server_data/files")
    ap.add_argument("--master-key", default="server_data/master.key")
    ap.add_argument("--token", default=os.environ.get("SYNTECX_TOKEN"), help="shared transfer token (or env SYNTECX_TOKEN)")
    a = ap.parse_args()
    if not a.token:
        sys.exit("Set --token or SYNTECX_TOKEN")
    os.makedirs(os.path.dirname(a.master_key), exist_ok=True)
    s = Server(a.host, a.port, a.cert, a.key, a.storage, a.token, a.master_key)
    print(f"[*] Secure file server listening on {a.host}:{s.port} (TLS)")
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        s.stop()
