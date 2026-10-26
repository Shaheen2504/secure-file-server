"""Regression: the server log must not contain the DH shared secret or anything that yields the session key."""

import logging
import re
import unittest

from support import ServerTestCase, server  # adds src/ to sys.path

from crypto_utils import derive_session_key  # noqa: E402


class CollectLogs(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


class SessionKeyLoggingTests(ServerTestCase):
    def test_log_does_not_reveal_session_key(self):
        logs = CollectLogs()
        server.log.addHandler(logs)
        self.addCleanup(server.log.removeHandler, logs)

        # 127-bit prime so the shared value is a long number, not a coincidence like "6"
        _, session_key, _ = self.open_session(p=str(2**127 - 1), g="3")

        text = "\n".join(logs.lines)
        self.assertIn("DH: Session key established", text)
        for number in re.findall(r"\d+", text):
            self.assertFalse(derive_session_key(int(number)) == session_key,
                             f"log line reveals DH shared value {number}")


if __name__ == "__main__":
    unittest.main()
