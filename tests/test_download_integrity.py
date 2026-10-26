"""Regression: tampered, reordered or truncated downloads must fail and leave no file behind."""

import os
import socket
import struct
import unittest
from unittest import mock

from support import ServerTestCase, client, quiet  # adds src/ to sys.path

from crypto_utils import aes_encrypt, compute_mac  # noqa: E402
from protocol import pack_chunk, send_frame  # noqa: E402

DATA = os.urandom(3000)  # three chunks: 1024 + 1024 + 952 bytes


class DownloadIntegrityTests(ServerTestCase):
    """The test plays the server: it queues crafted frames, then runs the real client download."""

    def setUp(self):
        super().setUp()
        self.session_key = os.urandom(32)
        self.aes_key = self.session_key[:16]
        self.client_sock, self.fake_server = socket.socketpair()
        self.client_sock.settimeout(5)
        self.addCleanup(self.client_sock.close)
        self.addCleanup(self.fake_server.close)

    def chunk(self, seq, data):
        encrypted = aes_encrypt(data, self.aes_key)
        return pack_chunk(seq, compute_mac(encrypted, seq, self.session_key), encrypted)

    def good_chunks(self):
        return [self.chunk(i, DATA[i * 1024:(i + 1) * 1024]) for i in range(3)]

    def run_download(self, frames, eof=True, close=False):
        for frame in frames:
            send_frame(self.fake_server, frame)
        if eof:
            send_frame(self.fake_server, b"")
        if close:
            self.fake_server.shutdown(socket.SHUT_WR)  # server stops sending mid-transfer
        return quiet(client.download_file, self.client_sock, "GET f.bin", "f.bin",
                     self.aes_key, self.session_key)

    def assert_failed_cleanly(self, connected, output, reason):
        self.assertFalse(connected, "client must end the session after a failed download")
        self.assertIn(reason, output)
        self.assertIn("DOWNLOAD FAILED", output)
        self.assertNotIn("downloaded successfully", output)
        self.assertEqual(sorted(p.name for p in self.work_dir.iterdir()), [])

    def test_valid_transfer_succeeds(self):
        connected, output = self.run_download(self.good_chunks())
        self.assertTrue(connected)
        self.assertIn("downloaded successfully", output)
        self.assertEqual((self.work_dir / "downloaded_f.bin").read_bytes(), DATA)
        self.assertEqual([p.name for p in self.work_dir.iterdir()], ["downloaded_f.bin"])

    def test_tampered_ciphertext(self):
        frames = self.good_chunks()
        frames[1] = frames[1][:-1] + bytes([frames[1][-1] ^ 1])
        self.assert_failed_cleanly(*self.run_download(frames), "MAC VERIFICATION FAILED")

    def test_tampered_mac(self):
        frames = self.good_chunks()
        frames[2] = frames[2][:4] + bytes(32) + frames[2][36:]
        self.assert_failed_cleanly(*self.run_download(frames), "MAC VERIFICATION FAILED")

    def test_tampered_first_chunk(self):
        frames = self.good_chunks()
        frames[0] = frames[0][:-1] + bytes([frames[0][-1] ^ 1])
        self.assert_failed_cleanly(*self.run_download(frames), "MAC VERIFICATION FAILED")

    def test_reordered_chunks(self):
        frames = self.good_chunks()
        frames[0], frames[1] = frames[1], frames[0]
        self.assert_failed_cleanly(*self.run_download(frames), "OUT OF ORDER PACKET")

    def test_replayed_chunk(self):
        frames = self.good_chunks()
        frames[1] = frames[0]
        self.assert_failed_cleanly(*self.run_download(frames), "OUT OF ORDER PACKET")

    def test_malformed_short_frame(self):
        frames = self.good_chunks()
        frames[1] = b"\x00\x00\x00\x01short"
        self.assert_failed_cleanly(*self.run_download(frames), "MALFORMED PACKET")

    def test_connection_closed_before_eof(self):
        result = self.run_download(self.good_chunks()[:2], eof=False, close=True)
        self.assert_failed_cleanly(*result, "Connection lost")

    def test_connection_closed_mid_frame(self):
        self.fake_server.sendall(struct.pack("!I", 500) + b"partial")
        result = self.run_download(self.good_chunks()[:0], eof=False, close=True)
        self.assert_failed_cleanly(*result, "Connection lost")

    def test_connection_reset_mid_transfer_leaves_no_part_file(self):
        frames = self.good_chunks()
        for frame in frames[:1]:
            send_frame(self.fake_server, frame)
        real_recv_frame = client.recv_frame
        calls = []

        def reset_on_second_call(sock):
            calls.append(1)
            if len(calls) == 2:
                raise ConnectionResetError("connection reset by peer")
            return real_recv_frame(sock)

        with mock.patch.object(client, "recv_frame", reset_on_second_call):
            with self.assertRaises(ConnectionResetError):
                quiet(client.download_file, self.client_sock, "GET f.bin", "f.bin",
                      self.aes_key, self.session_key)
        self.assertEqual(sorted(p.name for p in self.work_dir.iterdir()), [])

    def test_failed_second_copy_keeps_existing_file(self):
        existing = self.work_dir / "downloaded_f.bin"
        existing.write_bytes(b"earlier good copy")
        frames = self.good_chunks()
        frames[1] = frames[1][:-1] + bytes([frames[1][-1] ^ 1])
        with mock.patch("builtins.input", return_value="y"):
            connected, output = self.run_download(frames)
        self.assertFalse(connected)
        self.assertIn("DOWNLOAD FAILED", output)
        self.assertEqual(existing.read_bytes(), b"earlier good copy")
        self.assertEqual([p.name for p in self.work_dir.iterdir()], ["downloaded_f.bin"])

    @unittest.expectedFailure
    def test_dropped_final_chunk_is_detected(self):
        """Known protocol limitation: the EOF frame is not authenticated and the
        chunk count is never sent, so an attacker who simply drops the final
        chunk frames causes a truncated file to be accepted. The remaining
        chunks verify with consecutive sequence numbers, and the server's
        genuine EOF frame ends the transfer. Here chunk 3 of 3 is dropped.
        Fixing it needs an authenticated final frame (a protocol change)."""
        connected, output = self.run_download(self.good_chunks()[:2])
        self.assertIn("DOWNLOAD FAILED", output)


if __name__ == "__main__":
    unittest.main()
