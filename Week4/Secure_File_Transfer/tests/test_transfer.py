import os, sys, tempfile, threading, unittest, glob
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gen_cert
from client import Client, TransferError
from server import Server

TOKEN, PW = "test-token", "correct horse battery staple"


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.crt, cls.key, _ = gen_cert.generate(os.path.join(cls.tmp, "certs"))
        cls.storage = os.path.join(cls.tmp, "files")
        cls.srv = Server("127.0.0.1", 0, cls.crt, cls.key, cls.storage, TOKEN, os.path.join(cls.tmp, "master.key"))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.data = b"TOP-SECRET-MARKER " + os.urandom(700_000)
        cls.src = os.path.join(cls.tmp, "secret.bin")
        open(cls.src, "wb").write(cls.data)

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()

    def client(self, token=TOKEN, cert=None):
        return Client("localhost", self.srv.port, cert or self.crt, token)

    def test_1_roundtrip_and_encrypted_at_rest(self):
        c = self.client(); c.upload(self.src, PW, chunk_size=64 * 1024, progress=lambda *_: None)
        out = os.path.join(self.tmp, "out.bin"); c.download("secret.bin", out, PW); c.close()
        self.assertEqual(open(out, "rb").read(), self.data)
        for p in glob.glob(self.storage + "/*/*.chunk"):           # nothing readable on disk
            self.assertNotIn(b"TOP-SECRET-MARKER", open(p, "rb").read())

    def test_2_wrong_password(self):
        c = self.client()
        with self.assertRaises(TransferError): c.download("secret.bin", os.path.join(self.tmp, "x"), "wrong")
        c.close()

    def test_3_wrong_token(self):
        with self.assertRaises(Exception): self.client(token="bad")

    def test_4_resume(self):
        src = os.path.join(self.tmp, "big.bin"); data = os.urandom(500_000); open(src, "wb").write(data)
        c = self.client()
        with self.assertRaises(ConnectionAbortedError):
            c.upload(src, PW, chunk_size=50_000, interrupt_after=3, progress=lambda *_: None)
        c.close()
        msgs = []; c = self.client(); c.upload(src, PW, chunk_size=50_000, progress=msgs.append)
        out = os.path.join(self.tmp, "big.out"); c.download("big.bin", out, PW); c.close()
        self.assertTrue(any("resuming at chunk 3" in m for m in msgs))
        self.assertEqual(open(out, "rb").read(), data)

    def test_5_tamper_on_disk_detected(self):
        src = os.path.join(self.tmp, "t.bin"); open(src, "wb").write(os.urandom(100_000))
        c = self.client(); c.upload(src, PW, chunk_size=40_000, progress=lambda *_: None)
        from common import file_id
        p = os.path.join(self.storage, file_id("t.bin"), "00000001.chunk")
        b = bytearray(open(p, "rb").read()); b[20] ^= 1; open(p, "wb").write(bytes(b))
        with self.assertRaises(TransferError): c.download("t.bin", os.path.join(self.tmp, "t.out"), PW)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "t.out")))

    def test_6_path_traversal_rejected(self):
        c = self.client()
        with self.assertRaises(Exception): c.download("../../etc/passwd", "x", PW)

    def test_7_mitm_wrong_cert_rejected(self):
        other, _, _ = gen_cert.generate(os.path.join(self.tmp, "evil"))
        with self.assertRaises(Exception): self.client(cert=other)


if __name__ == "__main__":
    unittest.main(verbosity=2)
