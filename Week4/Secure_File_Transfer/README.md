# Syntecxhub_Secure_File_Transfer  (Cyber Security – Project 2)

Encrypted client/server file upload & download with chunking, integrity checks, resumable uploads and
encrypted storage on the server disk. Python 3.9+, one dependency (`cryptography`).

## Quick start
```bash
pip install -r requirements.txt
python gen_cert.py                                   # creates certs/server.crt + server.key
export SYNTECX_TOKEN="shared-transfer-token"
python server.py                                     # terminal 1 (127.0.0.1:9443)

export SYNTECX_TOKEN="shared-transfer-token"         # terminal 2
python client.py upload report.pdf                   # prompts for an encryption password
python client.py list
python client.py download report.pdf -o copy.pdf
python tests/test_transfer.py                        # 7 tests incl. tamper / MITM / resume
```

## How it works
| Layer | Mechanism | Protects against |
|---|---|---|
| Transport | TLS 1.2+ (ECDSA P-256 cert), **client pins** the server cert | Eavesdropping, man-in-the-middle |
| Auth | HMAC-SHA256 challenge/response using shared token (token never sent) | Unauthorised clients |
| Content | **AES-256-GCM** per chunk, key = scrypt(password, salt); AAD binds file name + chunk index + chunk count | Server compromise, reordering, truncation, chunk swapping |
| Integrity | **HMAC-SHA256** per chunk (verified by server on upload, client on download) + final SHA-256 of the whole file | Corruption / tampering in transit |
| At rest | Each chunk wrapped again with AES-256-GCM using a server master key (`master.key`, mode 0600) | Stolen disk / backups, on-disk tampering |
| Retrieval | Names whitelisted (`[A-Za-z0-9._ -]`), stored under `sha256(name)` → no path traversal | Directory traversal |

**Chunking & resume:** files are split (default 256 KB). `INIT` returns how many chunks the server already holds;
the client continues from there using the same salt/key (`tests/test_transfer.py::test_4_resume`).

## Files
`server.py` · `client.py` · `common.py` (framing, KDFs, HMAC) · `gen_cert.py` · `docs/THREAT_MODEL.md` · `tests/`

## Known limitations
- Shared token + password are symmetric secrets; use a secrets manager / per-user keys for production.
- No per-user accounts, quotas, rate limiting or download resume (extend as a bonus task).
- Server keeps the master key on the same host – use an HSM/KMS in real deployments.
