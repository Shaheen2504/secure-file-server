import os
import unittest

from support import ServerTestCase  # adds src/ to sys.path

from crypto_utils import aes_decrypt, aes_encrypt  # noqa: E402
from protocol import recv_frame, send_frame  # noqa: E402


class EncryptedSessionTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        (self.files_dir / "notes.txt").write_bytes(b"x" * 44)
        self.sock, self.session_key, self.aes_key = self.open_session()

    def command(self, cmd):
        send_frame(self.sock, aes_encrypt(cmd, self.aes_key))
        return aes_decrypt(recv_frame(self.sock), self.aes_key).decode()

    def test_file_commands(self):
        self.assertEqual(self.command("LIST"), "notes.txt")
        self.assertEqual(self.command("GETSIZE notes.txt"), "44 bytes")
        self.assertIn("Permissions:", self.command("INFO notes.txt"))
        self.assertEqual(self.command("GETSIZE missing.txt"), "ERROR: File not found")
        self.assertEqual(self.command("FOO"), "ERROR: Unknown command")
        self.assertEqual(self.command("QUIT"), "GOODBYE")

    def test_multi_chunk_download_is_byte_identical(self):
        data = os.urandom(3000)  # 3 chunks of up to 1024 bytes
        (self.files_dir / "big.bin").write_bytes(data)
        connected, output = self.download(self.sock, "big.bin", self.aes_key, self.session_key)
        self.assertTrue(connected)
        self.assertEqual((self.work_dir / "downloaded_big.bin").read_bytes(), data)
        self.assertEqual(output.count("[Cipher]"), 3)
        # Session still usable afterwards
        self.assertEqual(self.command("GETSIZE big.bin"), "3000 bytes")

    def test_download_missing_file(self):
        connected, output = self.download(self.sock, "missing.txt", self.aes_key, self.session_key)
        self.assertTrue(connected)
        self.assertIn("FILE NOT AVAILABLE", output)
        self.assertFalse((self.work_dir / "downloaded_missing.txt").exists())


if __name__ == "__main__":
    unittest.main()
