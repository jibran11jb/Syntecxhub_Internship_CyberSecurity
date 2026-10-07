#!/usr/bin/env python3
"""Client: E2E AES-256-GCM per chunk + HMAC per chunk + TLS with certificate pinning + resumable upload."""
import argparse, getpass, hashlib, hmac, math, os, socket, ssl, sys
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from common import *


class TransferError(Exception):
    pass


class Client:
    def __init__(self, host, port, cafile, token):
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)   # trust ONLY the pinned cert
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.sock = ctx.wrap_socket(socket.create_connection((host, port), timeout=30), server_hostname=host)
        self.mac_key = derive_mac_key(token)
        challenge = bytes.fromhex(recv_json(self.sock)["challenge"])
        send_json(self.sock, {"proof": hmac.new(self.mac_key, b"hello" + challenge, hashlib.sha256).hexdigest()})
        if not recv_json(self.sock).get("ok"):
            raise TransferError("authentication failed (wrong token?)")

    def close(self):
        self.sock.close()

    def _call(self, obj):
        send_json(self.sock, obj)
        r = recv_json(self.sock)
        if not r.get("ok"):
            raise TransferError(r.get("error", "server error"))
        return r

    def upload(self, path, password, chunk_size=DEFAULT_CHUNK, interrupt_after=None, progress=print):
        name = safe_name(os.path.basename(path))
        size = os.path.getsize(path)
        nchunks = math.ceil(size / chunk_size)
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                h.update(blk)
        r = self._call(dict(cmd="INIT", name=name, size=size, chunk_size=chunk_size, nchunks=nchunks,
                            salt=os.urandom(16).hex()))
        key = AESGCM(derive_enc_key(password, bytes.fromhex(r["salt"])))
        start = r["next_chunk"]
        if start:
            progress(f"resuming at chunk {start}/{nchunks}")
        fid = file_id(name)
        with open(path, "rb") as f:
            for i in range(start, nchunks):
                if interrupt_after is not None and i - start >= interrupt_after:
                    raise ConnectionAbortedError("simulated interruption")
                f.seek(i * chunk_size)
                nonce = os.urandom(12)
                blob = nonce + key.encrypt(nonce, f.read(chunk_size), aad(name, i, nchunks))
                send_json(self.sock, dict(cmd="CHUNK", name=name, index=i))
                send_frame(self.sock, blob)
                send_frame(self.sock, chunk_mac(self.mac_key, fid, i, blob))
                if not (rr := recv_json(self.sock)).get("ok"):
                    raise TransferError(rr.get("error"))
        self._call(dict(cmd="COMPLETE", name=name, sha256=h.hexdigest()))
        return h.hexdigest()

    def download(self, name, out_path, password):
        name = safe_name(name)
        send_json(self.sock, dict(cmd="DOWNLOAD", name=name))
        m = recv_json(self.sock)
        if not m.get("ok"):
            raise TransferError(m.get("error"))
        key = AESGCM(derive_enc_key(password, bytes.fromhex(m["salt"])))
        h, fid, tmp = hashlib.sha256(), file_id(name), out_path + ".part"
        try:
            with open(tmp, "wb") as f:
                for i in range(m["nchunks"]):
                    blob = recv_frame(self.sock)
                    if blob == ERR_MARK:
                        raise TransferError("server storage integrity failure")
                    if not hmac.compare_digest(recv_frame(self.sock), chunk_mac(self.mac_key, fid, i, blob)):
                        raise TransferError(f"HMAC mismatch on chunk {i} (tampered in transit)")
                    try:
                        plain = key.decrypt(blob[:12], blob[12:], aad(name, i, m["nchunks"]))
                    except InvalidTag:
                        raise TransferError("decryption failed (wrong password or corrupted data)")
                    h.update(plain)
                    f.write(plain)
            if h.hexdigest() != m["sha256"]:
                raise TransferError("final SHA-256 mismatch")
            os.replace(tmp, out_path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        return h.hexdigest()

    def list(self):
        return self._call(dict(cmd="LIST"))["files"]


def main():
    ap = argparse.ArgumentParser(description="Encrypted file transfer client")
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--cert", default="certs/server.crt", help="pinned server certificate")
    ap.add_argument("--token", default=os.environ.get("SYNTECX_TOKEN"))
    ap.add_argument("--password", default=os.environ.get("SYNTECX_PASSWORD"), help="file encryption password (prompted if omitted)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("upload"); u.add_argument("file"); u.add_argument("--chunk-kb", type=int, default=256)
    d = sub.add_parser("download"); d.add_argument("name"); d.add_argument("-o", "--out")
    sub.add_parser("list")
    a = ap.parse_args()
    if not a.token:
        sys.exit("Set --token or SYNTECX_TOKEN")
    c = Client(a.host, a.port, a.cert, a.token)
    try:
        if a.cmd == "list":
            for f in c.list():
                print(f"{f['name']:40} {f['size']:>12} bytes  {'complete' if f['complete'] else 'PARTIAL'}")
            return
        pw = a.password or getpass.getpass("Encryption password: ")
        if a.cmd == "upload":
            print("uploaded, sha256 =", c.upload(a.file, pw, a.chunk_kb * 1024))
        else:
            print("downloaded, sha256 =", c.download(a.name, a.out or a.name, pw))
    except TransferError as e:
        sys.exit(f"error: {e}")
    finally:
        c.close()


if __name__ == "__main__":
    main()
