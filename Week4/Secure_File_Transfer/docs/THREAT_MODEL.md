# Threat Model & Mitigations

**Assets:** file contents, file names/sizes, encryption password, transfer token, server master key, TLS private key.
**Actors:** passive network eavesdropper, active MITM, malicious/unauthenticated client, server-disk thief, curious/compromised server admin, malicious insider uploading odd file names.

| # | Threat | Impact | Mitigation in this project | Residual risk |
|---|---|---|---|---|
| 1 | **Man-in-the-middle** (rogue Wi-Fi, ARP spoof, DNS hijack) presents its own cert | Plaintext capture, tampering | TLS with **certificate pinning** (client trusts only `server.crt`; verified in `test_7`); hostname check; TLS ≥ 1.2; E2E AES-GCM means even a TLS break reveals only ciphertext | First distribution of `server.crt` must be authentic (compare SHA-256 fingerprint out-of-band) |
| 2 | **Key management failures** (weak/leaked keys) | Full decryption | scrypt (N=2^15) for password → key; random 16-byte salt per file; random 96-bit GCM nonces; master key file `0600` and generated with `os.urandom`; keys never logged or transmitted | Weak passwords are brute-forceable offline; rotate token/password; use KMS/HSM in production |
| 3 | Tampering in transit or on disk | Corrupt / malicious data accepted | HMAC per chunk, GCM tags (at rest and E2E), AAD binds chunk to file+position, final SHA-256 check; partial downloads written to `.part` and deleted on failure (`test_5`) | – |
| 4 | Replay / reorder / truncation of chunks | Wrong or partial file accepted | Index in HMAC and AAD, sequential-only writes, total chunk count in AAD, `COMPLETE` requires all chunks | Whole-file replay of an *old valid* upload is possible; add version counters / timestamps |
| 5 | Unauthenticated access | Data theft / storage abuse | HMAC challenge-response with fresh nonce per connection (`test_3`) | Single shared token – no per-user revocation |
| 6 | Path traversal (`../../etc/passwd`) | Arbitrary file read/write | Strict filename whitelist + storage by hash of name (`test_6`) | – |
| 7 | Disk theft / backup leak | Data exposure | Data AES-GCM encrypted twice (E2E + at-rest) | Metadata (file name, size) is stored in clear in `meta.json` |
| 8 | DoS (huge frames, many connections) | Unavailable service | 8 MB frame cap, socket timeouts, thread per connection | Add rate limiting, quotas, connection caps |
| 9 | Nonce reuse in AES-GCM | Catastrophic key/plaintext leak | Fresh random 96-bit nonce per chunk (≈2^-32 collision risk after 2^32 chunks per key; key is per-file via salt) | Fine for this scale |

## Design decisions
- **Why encrypt twice?** E2E encryption keeps the server blind to content; at-rest encryption protects the stored ciphertext and its integrity independently of client behaviour.
- **Why HMAC when GCM already authenticates?** The server cannot verify the E2E GCM tag (it lacks the key); the token-derived HMAC lets the server reject forged/corrupt chunks before storing them, and the project brief asks for it explicitly.
