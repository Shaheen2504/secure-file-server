"""
Wire framing shared by server and client.

Frame:        LENGTH (4 bytes, big-endian) | PAYLOAD
File chunk:   SEQ (4) | MAC (32) | ENCRYPTED_DATA   (sent as a frame payload)
"""

import struct

MAC_SIZE = 32


def recv_exact(conn, size):
    """Receive exact number of bytes"""
    data = b''
    while len(data) < size:
        packet = conn.recv(size - len(data))
        if not packet:
            return None
        data += packet
    return data


def send_frame(conn, payload):
    """Send payload with a 4-byte length prefix"""
    conn.sendall(struct.pack("!I", len(payload)) + payload)


def recv_frame(conn):
    """
    Receive one length-prefixed frame
    Returns: payload bytes (b'' for a zero-length frame), or None if the connection closed
    """
    length_bytes = recv_exact(conn, 4)
    if not length_bytes:
        return None
    return recv_exact(conn, struct.unpack("!I", length_bytes)[0])


def pack_chunk(seq_no, mac, encrypted_data):
    return struct.pack("!I", seq_no) + mac + encrypted_data


def unpack_chunk(packet):
    """Returns: (seq_no, mac, encrypted_data)"""
    seq_no = struct.unpack("!I", packet[:4])[0]
    return seq_no, packet[4:4 + MAC_SIZE], packet[4 + MAC_SIZE:]
