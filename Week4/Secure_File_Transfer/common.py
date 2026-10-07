"""Shared protocol helpers: framing, key derivation, HMAC, filename safety."""
import hashlib, hmac, json, os, re, struct

MAX_FRAME = 8 * 1024 * 1024
DEFAULT_CHUNK = 256 * 1024
ERR_MARK = b"\x00ERR"


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("connection closed")
        buf += part
    return bytes(buf)


def send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock) -> bytes:
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    return recv_exact(sock, n)


def send_json(sock, obj):
    send_frame(sock, json.dumps(obj).encode())


def recv_json(sock):
    return json.loads(recv_frame(sock))


def derive_enc_key(password: str, salt: bytes) -> bytes:
    """End-to-end AES-256 key from the user's password (server never sees it)."""
    return hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)


def derive_mac_key(token: str) -> bytes:
    """HMAC key from the shared transfer token (lets the server verify integrity)."""
    return hashlib.pbkdf2_hmac("sha256", token.encode(), b"syntecxhub-transfer-mac-v1", 100_000)


def chunk_mac(mac_key: bytes, file_id: str, index: int, blob: bytes) -> bytes:
    return hmac.new(mac_key, file_id.encode() + struct.pack(">Q", index) + blob, hashlib.sha256).digest()


def file_id(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def safe_name(name: str) -> str:
    """Reject path traversal / odd names. Only a plain file name is accepted."""
    base = os.path.basename(name.replace("\\", "/"))
    if base != name or base in ("", ".", "..") or not re.fullmatch(r"[A-Za-z0-9._ \-]{1,128}", base):
        raise ValueError("invalid file name")
    return base


def aad(name: str, index: int, nchunks: int) -> bytes:
    """Binds each ciphertext chunk to its file, position and total count (anti-reorder/truncation)."""
    return f"{name}|{index}|{nchunks}".encode()
