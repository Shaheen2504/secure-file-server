import socket
import threading
import time
import unittest

import support  # noqa: F401  (adds src/ to sys.path)
from protocol import pack_chunk, recv_exact, recv_frame, send_frame, unpack_chunk


class FramingTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.b.settimeout(5)
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)

    def test_recv_exact_reassembles_fragmented_data(self):
        def dribble():
            for byte in b"fragmented":
                self.a.sendall(bytes([byte]))
                time.sleep(0.001)
        threading.Thread(target=dribble).start()
        self.assertEqual(recv_exact(self.b, 10), b"fragmented")

    def test_recv_exact_returns_none_on_early_close(self):
        self.a.sendall(b"abc")
        self.a.close()
        self.assertIsNone(recv_exact(self.b, 10))

    def test_frames_round_trip_including_empty_eof_frame(self):
        for payload in (b"x", b"", b"y" * 5000):
            send_frame(self.a, payload)
        self.assertEqual(recv_frame(self.b), b"x")
        self.assertEqual(recv_frame(self.b), b"")
        self.assertEqual(recv_frame(self.b), b"y" * 5000)

    def test_recv_frame_returns_none_when_closed(self):
        self.a.close()
        self.assertIsNone(recv_frame(self.b))

    def test_chunk_layout(self):
        mac = bytes(range(32))
        packet = pack_chunk(7, mac, b"ciphertext")
        self.assertEqual(packet[:4], (7).to_bytes(4, "big"))
        self.assertEqual(unpack_chunk(packet), (7, mac, b"ciphertext"))


if __name__ == "__main__":
    unittest.main()
