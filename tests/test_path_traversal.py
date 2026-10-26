"""Regression: file commands must not reach outside the served files/ folder."""

import os
import unittest

from support import ServerTestCase  # adds src/ to sys.path

from crypto_utils import aes_decrypt, aes_encrypt  # noqa: E402
from protocol import recv_frame, send_frame  # noqa: E402


class PathTraversalTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        (self.files_dir / "public.txt").write_bytes(b"public" * 10)
        self.secret = self.work_dir / "credentials.txt"  # outside files/
        self.secret.write_bytes(b"alice:real-secret")
        os.symlink(self.secret, self.files_dir / "link.txt")
        (self.files_dir / "subdir").mkdir()
        self.sock, self.session_key, self.aes_key = self.open_session()

        self.escapes = [
            os.path.relpath(self.secret, self.files_dir),  # ../.../credentials.txt
            str(self.secret),                              # absolute path
            "link.txt",                                    # symlink pointing outside
        ]

    def command(self, cmd):
        send_frame(self.sock, aes_encrypt(cmd, self.aes_key))
        return aes_decrypt(recv_frame(self.sock), self.aes_key).decode()

    def test_info_and_getsize_reject_escapes(self):
        for name in self.escapes + ["subdir", "."]:
            with self.subTest(name=name):
                self.assertEqual(self.command(f"GETSIZE {name}"), "ERROR: File not found")
                self.assertEqual(self.command(f"INFO {name}"), "ERROR: File not found")

    def test_get_rejects_escapes_and_directories(self):
        for name in self.escapes + ["subdir", "."]:
            with self.subTest(name=name):
                connected, output = self.download(self.sock, name, self.aes_key, self.session_key)
                self.assertTrue(connected)
                self.assertIn("FILE NOT AVAILABLE", output)
                self.assertNotIn("real-secret", output)

    def test_nul_byte_name_is_not_found_and_session_survives(self):
        # realpath() raises ValueError on an embedded NUL; must be "not found", not a dropped connection
        self.assertEqual(self.command("GETSIZE a\x00b"), "ERROR: File not found")
        self.assertEqual(self.command("INFO a\x00b"), "ERROR: File not found")
        connected, output = self.download(self.sock, "a\x00b", self.aes_key, self.session_key)
        self.assertTrue(connected)
        self.assertIn("FILE NOT AVAILABLE", output)
        self.assertEqual(self.command("GETSIZE public.txt"), "60 bytes")

    def test_normal_file_still_served(self):
        self.assertEqual(self.command("GETSIZE public.txt"), "60 bytes")
        connected, _ = self.download(self.sock, "public.txt", self.aes_key, self.session_key)
        self.assertTrue(connected)
        self.assertEqual((self.work_dir / "downloaded_public.txt").read_bytes(), b"public" * 10)


if __name__ == "__main__":
    unittest.main()
