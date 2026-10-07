# Syntecxhub_CVE_Scanner  (Cyber Security – Project 1)

A lightweight vulnerability / CVE scanner written in pure Python 3 (no third-party packages).

**Pipeline:** port connect → banner grab / service detection → map to CPE → query the NVD CVE API
(falls back to a local signature DB when offline) → Markdown + JSON report with severity and triage notes.

## Usage
```bash
python scanner.py 127.0.0.1                               # default common ports
python scanner.py 192.168.1.10 -p 21,22,80,443 --report out/report.md --json out/report.json
python scanner.py scanme.local --offline                  # no API calls, local signatures only
export NVD_API_KEY=xxxx                                   # optional: faster NVD rate limit
python tests/test_scanner.py                              # unit + end-to-end tests
```
Try it safely: run a fake service on localhost, e.g.
`python -c "import socket;s=socket.socket();s.bind(('127.0.0.1',2121));s.listen();exec('while 1:\n c,_=s.accept();c.send(b\"220 (vsFTPd 2.3.4)\\r\\n\");c.close()')"`
then `python scanner.py 127.0.0.1 -p 2121 --offline`.

## Features
- Threaded TCP banner grabbing; HTTP `HEAD` probe on web ports; TLS handshake (no cert validation) on 443/8443/993/995.
- Signature-based product/version extraction (OpenSSH, Apache, nginx, vsftpd, ProFTPD, Exim, PHP, OpenSSL, IIS, lighttpd, MySQL/MariaDB).
- NVD API 2.0 lookup by CPE (`virtualMatchString`), CVSS score/severity, CISA KEV flag, rate-limit aware.
- Offline signature DB (`data/signatures.json`) with version ranges – easy to extend.
- Severity bands (Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, Low) and P1–P4 triage guidance in the report.
- **Safety gate:** refuses non-private targets unless `--authorized` is passed.

## Limitations (be honest in your write-up)
- Version banners can be hidden/spoofed; Linux distros back-port patches, so matches are *possible*, never confirmed.
- Not a replacement for Nessus/OpenVAS/Nmap NSE; no active exploitation is performed (by design).
- Offline CVSS scores are approximate – verify on NVD.

## Docs
- `docs/RESPONSIBLE_DISCLOSURE.md` – disclosure and triage basics.
