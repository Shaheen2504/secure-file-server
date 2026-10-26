"""Shared test setup: puts src/ on sys.path and runs real server/client code over socketpairs."""

import contextlib
import logging
import io
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import auth  # noqa: E402
import client  # noqa: E402
import server  # noqa: E402
from crypto_utils import derive_aes_key  # noqa: E402

USERS = {"alice": "alice-test-secret", "bob": "bob-test-secret"}

server.log.setLevel(logging.INFO)


class SessionReady(logging.Handler):
    """Signals when the server has finished DH and is ready for encrypted commands.

    Needed because the handshake is unframed: if the client sends its first
    encrypted command before the server has read the client's DH public value,
    one recv() can return both and the key exchange fails (known protocol issue).
    """

    def __init__(self):
        super().__init__()
        self.event = threading.Event()

    def emit(self, record):
        if "AES encryption enabled" in record.getMessage():
            self.event.set()


def quiet(fn, *args, **kwargs):
    """Call fn with stdout captured. Returns (result, captured_text)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        result = fn(*args, **kwargs)
    return result, out.getvalue()


def serve(user_db=USERS):
    """Start the real per-client handler on one end of a socketpair; return the client end."""
    client_sock, server_sock = socket.socketpair()
    client_sock.settimeout(5)  # a protocol hang fails the test instead of blocking forever
    threading.Thread(target=server.process_client_connection,
                     args=(server_sock, ("test", 0), user_db), daemon=True).start()
    return client_sock


class ServerTestCase(unittest.TestCase):
    """Fresh lockout state, a temporary files/ directory and a temporary client working directory."""

    def setUp(self):
        auth.blocked_users.clear()
        auth.failed_logins.clear()

        files = tempfile.TemporaryDirectory()
        self.addCleanup(files.cleanup)
        self.files_dir = Path(files.name)
        patcher = mock.patch.object(server, "FILES_FOLDER", files.name)
        patcher.start()
        self.addCleanup(patcher.stop)

        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.work_dir = Path(work.name)
        old_cwd = os.getcwd()
        os.chdir(work.name)
        self.addCleanup(os.chdir, old_cwd)

    def open_session(self, p="23", g="5"):
        """Log in as alice and run DH. Returns (sock, session_key, aes_key)."""
        ready = SessionReady()
        server.log.addHandler(ready)
        self.addCleanup(server.log.removeHandler, ready)

        sock = serve()
        self.addCleanup(sock.close)
        ok, _ = quiet(client.perform_login, sock, "alice", USERS["alice"])
        self.assertTrue(ok)
        with mock.patch.dict(os.environ, {"P": p, "G": g}):
            session_key, _ = quiet(client.establish_shared_key, sock)
        self.assertIsNotNone(session_key)
        self.assertTrue(ready.event.wait(5), "server did not complete key exchange")
        return sock, session_key, derive_aes_key(session_key)

    def download(self, sock, filename, aes_key, session_key):
        """Run the real client GET. Returns (still_connected, printed_output)."""
        return quiet(client.download_file, sock, f"GET {filename}", filename, aes_key, session_key)
