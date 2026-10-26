"""
Server-side authentication: credential loading, challenge-response login
and account lockout.
"""

import logging
import secrets
import threading

from crypto_utils import auth_response

LOGIN_ATTEMPT_LIMIT = 3

log = logging.getLogger("fileserver")

blocked_users = {}
failed_logins = {}  # username -> consecutive failures, counted across connections
block_lock = threading.Lock()


def read_user_credentials(path):
    """Load user database (username:shared_secret per line)"""
    user_db = {}
    try:
        with open(path, 'r') as file:
            for line in file:
                line = line.strip()
                if ':' in line:
                    user, secret = line.split(':', 1)
                    user_db[user.strip()] = secret.strip()
    except FileNotFoundError:
        print(f"[SERVER] Warning: {path} not found")
    return user_db


def check_if_blocked(user):
    """Check account lock status"""
    with block_lock:
        return blocked_users.get(user, False)


def block_user_account(user):
    """Lock user account"""
    with block_lock:
        blocked_users[user] = True


def record_failed_login(user):
    """
    Count a wrong secret for a known user and lock the account at the limit
    Returns: attempts left before lockout
    """
    with block_lock:
        failed_logins[user] = failed_logins.get(user, 0) + 1
        if failed_logins[user] >= LOGIN_ATTEMPT_LIMIT:
            blocked_users[user] = True
        return max(0, LOGIN_ATTEMPT_LIMIT - failed_logins[user])


def clear_failed_logins(user):
    with block_lock:
        failed_logins.pop(user, None)


def verify_user_identity(conn, user_db):
    """
    Challenge-response authentication protocol
    Returns: (success_flag, username)
    """
    failed_attempts = 0
    current_user = None

    while failed_attempts < LOGIN_ATTEMPT_LIMIT:
        try:
            # Step 1: Get username
            username_data = conn.recv(1024)
            if not username_data:
                return False, None

            current_user = username_data.decode('utf-8').strip()
            log.info(f"AUTH: Username received: {current_user}")

            # Step 2: Check if blocked
            if check_if_blocked(current_user):
                conn.sendall("ACCOUNT_LOCKED".encode('utf-8'))
                log.info(f"AUTH: Account {current_user} is locked")
                return False, None

            # Step 3: Validate username exists
            if current_user not in user_db:
                conn.sendall("INVALID_USER".encode('utf-8'))
                failed_attempts += 1
                log.info(f"AUTH: Invalid username {current_user}, attempt {failed_attempts}")
                continue

            # Step 4: Send challenge (random nonce)
            random_nonce = secrets.token_hex(16)
            conn.sendall(random_nonce.encode('utf-8'))
            log.info(f"AUTH: Nonce sent to {current_user}")

            # Step 5: Get client's hash response
            client_response = conn.recv(1024).decode('utf-8').strip()

            # Step 6-7: Compare with expected hash
            if client_response == auth_response(random_nonce, user_db[current_user]):
                clear_failed_logins(current_user)
                conn.sendall("AUTH_SUCCESS".encode('utf-8'))
                log.info(f"AUTH: Success for {current_user}")
                return True, current_user
            else:
                # Count per user, not per connection, so reconnecting does not
                # reset the limit
                failed_attempts += 1
                attempts_left = record_failed_login(current_user)
                conn.sendall(f"AUTH_FAILED:{attempts_left}".encode('utf-8'))
                log.info(f"AUTH: Failed for {current_user}, attempt {failed_attempts}")
                if attempts_left == 0:
                    break

        except Exception as err:
            log.info(f"AUTH: Error during authentication: {err}")
            return False, None

    # Too many failures - lock account
    block_user_account(current_user)
    conn.sendall("ACCOUNT_LOCKED".encode('utf-8'))
    log.info(f"AUTH: Account {current_user} locked after {LOGIN_ATTEMPT_LIMIT} failed attempts")
    return False, None
