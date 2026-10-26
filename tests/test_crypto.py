import hashlib
import os
import unittest

import support  # noqa: F401  (adds src/ to sys.path)
from crypto_utils import aes_decrypt, aes_encrypt, auth_response, compute_mac, derive_aes_key, derive_session_key


class AesTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(16)

    def test_round_trip_across_block_boundaries(self):
        for size in (0, 1, 15, 16, 17, 1024, 3000):
            data = os.urandom(size)
            self.assertEqual(aes_decrypt(aes_encrypt(data, self.key), self.key), data)

    def test_strings_are_utf8_encoded(self):
        self.assertEqual(aes_decrypt(aes_encrypt("LIST", self.key), self.key), b"LIST")

    def test_random_iv_per_message(self):
        a, b = aes_encrypt(b"same", self.key), aes_encrypt(b"same", self.key)
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 32)  # 16-byte IV + one padded block

    def test_wrong_key_does_not_recover_plaintext(self):
        ct = aes_encrypt(b"secret file contents", self.key)
        try:
            self.assertNotEqual(aes_decrypt(ct, os.urandom(16)), b"secret file contents")
        except ValueError:
            pass  # bad padding is the usual outcome


class MacTests(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.data = aes_encrypt(b"chunk", self.key[:16])
        self.mac = compute_mac(self.data, 0, self.key)

    def test_construction(self):
        expected = hashlib.sha256(self.data + (0).to_bytes(4, "big") + self.key).digest()
        self.assertEqual(self.mac, expected)

    def test_detects_single_bit_flip(self):
        tampered = bytearray(self.data)
        tampered[-1] ^= 1
        self.assertNotEqual(compute_mac(bytes(tampered), 0, self.key), self.mac)

    def test_bound_to_sequence_number_and_key(self):
        self.assertNotEqual(compute_mac(self.data, 1, self.key), self.mac)
        self.assertNotEqual(compute_mac(self.data, 0, os.urandom(32)), self.mac)


class KeyDerivationTests(unittest.TestCase):
    def test_session_and_aes_keys(self):
        session_key = derive_session_key(12345)
        self.assertEqual(session_key, hashlib.sha256(b"12345").digest())
        self.assertEqual(derive_aes_key(session_key), session_key[:16])

    def test_auth_response(self):
        self.assertEqual(auth_response("abc", "pw"), hashlib.sha256(b"abcpw").hexdigest())


if __name__ == "__main__":
    unittest.main()
