import os, socket, sys, threading, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import scanner


def fake_service(banner):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(5)
    def run():
        while True:
            try: c, _ = s.accept()
            except OSError: return
            c.sendall(banner); c.close()
    threading.Thread(target=run, daemon=True).start()
    return s


class T(unittest.TestCase):
    def test_detect(self):
        d = scanner.detect_services(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu")
        self.assertEqual(d[0]["version"], "8.2p1")
        d = scanner.detect_services(80, "Server: Apache/2.4.49 (Unix)\r\nX-Powered-By: PHP/5.3.3")
        self.assertEqual({x["label"] for x in d}, {"Apache httpd", "PHP"})

    def test_cpe(self):
        self.assertEqual(scanner.to_cpe("openbsd", "openssh", "8.2p1"), "cpe:2.3:a:openbsd:openssh:8.2:p1")

    def test_offline_matching(self):
        db = scanner.load_offline_db()
        ids = lambda v, p, ver: {c["cve"] for c in scanner.match_offline(db, v, p, ver)}
        self.assertIn("CVE-2011-2523", ids("beasts", "vsftpd", "2.3.4"))
        self.assertNotIn("CVE-2011-2523", ids("beasts", "vsftpd", "3.0.5"))
        self.assertIn("CVE-2024-6387", ids("openbsd", "openssh", "9.2p1"))
        self.assertNotIn("CVE-2024-6387", ids("openbsd", "openssh", "9.8p1"))
        self.assertIn("CVE-2014-0160", ids("openssl", "openssl", "1.0.1f"))
        self.assertNotIn("CVE-2014-0160", ids("openssl", "openssl", "1.0.1g"))

    def test_end_to_end_offline(self):
        srv = fake_service(b"220 (vsFTPd 2.3.4)\r\n")
        port = srv.getsockname()[1]
        out = "/tmp/_scan_report.md"
        rc = scanner.main(["127.0.0.1", "-p", str(port), "--offline", "--report", out, "--json", "/tmp/_scan.json"])
        srv.close()
        self.assertEqual(rc, 0)
        self.assertIn("CVE-2011-2523", open(out).read())

    def test_public_refused(self):
        self.assertEqual(scanner.main(["8.8.8.8", "-p", "53", "--offline"]), 2)


if __name__ == "__main__":
    unittest.main()
