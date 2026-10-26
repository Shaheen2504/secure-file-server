"""Regression tests for the client-side GET download path."""

import os
import unittest
from unittest import mock

from support import ServerTestCase  # adds src/ to sys.path

from crypto_utils import aes_decrypt, aes_encrypt  # noqa: E402
from protocol import recv_frame, send_frame  # noqa: E402


class DownloadSizeTests(ServerTestCase):
    """Files smaller than ~32 bytes used to hang: the client read their first chunk twice."""

    def setUp(self):
        super().setUp()
        self.sock, self.session_key, self.aes_key = self.open_session()

    def command(self, cmd):
        send_frame(self.sock, aes_encrypt(cmd, self.aes_key))
        return aes_decrypt(recv_frame(self.sock), self.aes_key).decode()

    def test_every_size_downloads_intact_and_session_stays_usable(self):
        for size in (0, 1, 12, 15, 16, 31, 32, 47, 48, 1023, 1024, 1025):
            with self.subTest(size=size):
                name = f"f{size}.bin"
                data = os.urandom(size)
                (self.files_dir / name).write_bytes(data)
                connected, output = self.download(self.sock, name, self.aes_key, self.session_key)
                self.assertTrue(connected)
                self.assertIn("downloaded successfully", output)
                self.assertEqual((self.work_dir / f"downloaded_{name}").read_bytes(), data)
                self.assertEqual(self.command(f"GETSIZE {name}"), f"{size} bytes")

    def test_cancelled_small_download_leaves_stream_in_sync(self):
        (self.files_dir / "tiny.txt").write_bytes(b"Hello World\n")
        (self.work_dir / "downloaded_tiny.txt").write_bytes(b"old copy")
        with mock.patch("builtins.input", return_value="n"):
            connected, output = self.download(self.sock, "tiny.txt", self.aes_key, self.session_key)
        self.assertTrue(connected)
        self.assertIn("Download cancelled", output)
        self.assertEqual((self.work_dir / "downloaded_tiny.txt").read_bytes(), b"old copy")
        self.assertEqual(self.command("GETSIZE tiny.txt"), "12 bytes")

    def test_second_copy_gets_numbered_name(self):
        (self.files_dir / "tiny.txt").write_bytes(b"Hello World\n")
        (self.work_dir / "downloaded_tiny.txt").write_bytes(b"old copy")
        with mock.patch("builtins.input", return_value="y"):
            self.download(self.sock, "tiny.txt", self.aes_key, self.session_key)
        self.assertEqual((self.work_dir / "downloaded_tiny(2).txt").read_bytes(), b"Hello World\n")


if __name__ == "__main__":
    unittest.main()
