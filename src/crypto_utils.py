"""
Cryptographic helpers shared by server and client:
challenge-response hash, session key derivation, MAC and AES-128-CBC.
"""

import hashlib
import struct

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def auth_response(nonce, secret):
    """Challenge response: SHA256(nonce || shared_secret) as hex"""
    return hashlib.sha256((nonce + secret).encode('utf-8')).hexdigest()


def derive_session_key(shared_value):
    """Session key (32 bytes) = SHA256 of the Diffie-Hellman shared value"""
    return hashlib.sha256(str(shared_value).encode('utf-8')).digest()


def compute_mac(data, seq_no, session_key):
    """Compute MAC for integrity verification"""
    seq_bytes = struct.pack("!I", seq_no)
    return hashlib.sha256(data + seq_bytes + session_key).digest()


def derive_aes_key(session_key):
    """Derive 128-bit AES key from session key"""
    return session_key[:16]  # First 16 bytes for AES-128


def aes_encrypt(data, aes_key):
    """
    Encrypt data using AES-CBC
    Returns: IV (16 bytes) + ciphertext
    """
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    if isinstance(data, str):
        data = data.encode('utf-8')

    return iv + cipher.encrypt(pad(data, AES.block_size))


def aes_decrypt(encrypted_data, aes_key):
    """
    Decrypt data using AES-CBC
    encrypted_data = IV (16 bytes) + ciphertext
    Returns: plaintext bytes
    """
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
