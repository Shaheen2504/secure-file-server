import unittest

from support import USERS, ServerTestCase, auth, client, quiet, serve


class AuthTests(ServerTestCase):
    def login(self, sock, user, secret):
        ok, output = quiet(client.perform_login, sock, user, secret)
        return ok, output

    def test_correct_secret_succeeds(self):
        sock = serve()
        self.addCleanup(sock.close)
        ok, _ = self.login(sock, "alice", USERS["alice"])
        self.assertTrue(ok)

    def test_wrong_secret_reports_attempts_left(self):
        sock = serve()
        self.addCleanup(sock.close)
        ok, output = self.login(sock, "alice", "wrong")
        self.assertFalse(ok)
        self.assertIn("2 attempts remaining", output)

    def test_unknown_user_rejected(self):
        sock = serve()
        self.addCleanup(sock.close)
        ok, output = self.login(sock, "mallory", "x")
        self.assertFalse(ok)
        self.assertIn("Invalid username", output)

    def test_lockout_after_three_failures(self):
        sock = serve()
        self.addCleanup(sock.close)
        for _ in range(2):
            self.assertFalse(self.login(sock, "alice", "wrong")[0])
        # Third failure locks the account. The server sends AUTH_FAILED:0 and
        # ACCOUNT_LOCKED back-to-back without framing, so the client may see
        # them merged into one recv(); only the outcome is asserted here.
        self.assertFalse(self.login(sock, "alice", "wrong")[0])
        self.assertTrue(auth.check_if_blocked("alice"))

        # A new connection with the correct secret is still refused
        sock2 = serve()
        self.addCleanup(sock2.close)
        ok, output = self.login(sock2, "alice", USERS["alice"])
        self.assertFalse(ok)
        self.assertIn("Account is locked", output)

    def test_failures_count_across_connections(self):
        # Two wrong guesses, disconnect, repeat: must not give unlimited guesses
        for _ in range(2):
            sock = serve()
            for _ in range(2):
                self.assertFalse(self.login(sock, "alice", "wrong")[0])
            sock.close()
        self.assertTrue(auth.check_if_blocked("alice"))

    def test_successful_login_resets_failure_count(self):
        sock = serve()
        self.addCleanup(sock.close)
        for _ in range(2):
            self.login(sock, "alice", "wrong")
        self.assertTrue(self.login(sock, "alice", USERS["alice"])[0])
        sock2 = serve()
        self.addCleanup(sock2.close)
        ok, output = self.login(sock2, "alice", "wrong")
        self.assertIn("2 attempts remaining", output)
        self.assertFalse(auth.check_if_blocked("alice"))

    def test_lockout_is_per_user(self):
        auth.block_user_account("alice")
        sock = serve()
        self.addCleanup(sock.close)
        self.assertTrue(self.login(sock, "bob", USERS["bob"])[0])

    def test_credentials_file_parsing(self):
        path = self.work_dir / "creds.txt"
        path.write_text("alice: s1:with-colon \n\nnot a credential line\nbob:s2\n")
        self.assertEqual(auth.read_user_credentials(str(path)), {"alice": "s1:with-colon", "bob": "s2"})


if __name__ == "__main__":
    unittest.main()
