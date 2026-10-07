#!/usr/bin/env python3
"""Generate a self-signed TLS certificate (ECDSA P-256). The client PINS this cert (trusts only it)."""
import datetime, ipaddress, os, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate(outdir="certs", host="localhost"):
    os.makedirs(outdir, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    san = [x509.DNSName(host), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    kp, cp = os.path.join(outdir, "server.key"), os.path.join(outdir, "server.crt")
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(kp, 0o600)
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    fp = cert.fingerprint(hashes.SHA256()).hex()
    return cp, kp, fp


if __name__ == "__main__":
    cp, kp, fp = generate(*(sys.argv[1:3]))
    print(f"cert: {cp}\nkey:  {kp}\nSHA-256 fingerprint: {fp}\nCopy server.crt (only) to clients.")
