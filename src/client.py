"""
Secure File Server Client
Authentication, Diffie-Hellman key exchange, encrypted commands and file download
"""

import os
import re
import secrets
import socket

from crypto_utils import aes_decrypt, aes_encrypt, auth_response, compute_mac, derive_aes_key, derive_session_key
from protocol import MAC_SIZE, recv_frame, send_frame, unpack_chunk

#  CONFIGURATION
SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432

#  HELPER FUNCTIONS

def get_available_filename(base_name):
    """Generate next available filename if file exists"""
    if not os.path.exists(base_name):
        return base_name

    name, ext = os.path.splitext(base_name)
    pattern = re.compile(rf"^{re.escape(name)}\((\d+)\){re.escape(ext)}$")

    max_number = 1
    for existing_file in os.listdir('.'):
        if existing_file == base_name:
            continue
        match = pattern.match(existing_file)
        if match:
            max_number = max(max_number, int(match.group(1)))

    return f"{name}({max_number + 1}){ext}"

#  AUTHENTICATION

def perform_login(conn, user_name, secret_key):
    """
    Authenticate with server using challenge-response
    Returns: True on success, False on failure
    """
    try:
        # Step 1: Send username to server
        conn.sendall(user_name.encode('utf-8'))
        print(f"[CLIENT] Sent username: {user_name}")

        # Step 2: Receive response (nonce or error)
        server_msg = conn.recv(1024).decode('utf-8').strip()

        if server_msg == "ACCOUNT_LOCKED":
            print("[CLIENT] Account is locked")
            return False

        if server_msg == "INVALID_USER":
            print("[CLIENT] Invalid username")
            return False

        challenge_nonce = server_msg
        print("[CLIENT] Received nonce from server")

        # Step 3-4: Send SHA256(nonce || secret)
        conn.sendall(auth_response(challenge_nonce, secret_key).encode('utf-8'))

        # Step 5: Get authentication result
        auth_result = conn.recv(1024).decode('utf-8').strip()

        if auth_result == "AUTH_SUCCESS":
            print("[CLIENT] Authentication successful!")
            return True
        elif auth_result.startswith("AUTH_FAILED"):
            splits = auth_result.split(':')
            if len(splits) > 1:
                print(f"[CLIENT] Authentication failed. {splits[1]} attempts remaining")
            else:
                print("[CLIENT] Authentication failed")
            return False
        elif auth_result == "ACCOUNT_LOCKED":
            print("[CLIENT] Account locked due to too many failed attempts")
            return False

        return False

    except Exception as err:
        print(f"[CLIENT] Authentication error: {err}")
        return False

#  DIFFIE-HELLMAN

def establish_shared_key(conn):
    """
    Client-side Diffie-Hellman key exchange
    Returns: session key (32 bytes) or None
    """
    try:
        # Step 1: Get DH parameters from environment
        prime_val = int(os.environ.get('P', '23'))
        base_val = int(os.environ.get('G', '5'))

        print(f"[CLIENT] Using DH parameters: p={prime_val}, g={base_val}")
        conn.sendall(f"{prime_val},{base_val}".encode('utf-8'))

        # Step 2-3: Private and public values
        client_private = secrets.randbelow(prime_val - 2) + 1
        client_public = pow(base_val, client_private, prime_val)

        # Step 4: Receive server's public value
        server_public = int(conn.recv(1024).decode('utf-8').strip())
        print("[CLIENT] Received server public key")

        # Step 5: Send our public value
        conn.sendall(str(client_public).encode('utf-8'))
        print("[CLIENT] Sent client public key")

        # Step 6: Calculate shared secret
        shared_val = pow(server_public, client_private, prime_val)

        print("[CLIENT] Session key established")
        return derive_session_key(shared_val)

    except Exception as err:
        print(f"[CLIENT] Error during key exchange: {err}")
        return None

#  FILE DOWNLOAD

def receive_chunk(packet, expected_seq, aes_key, session_key):
    """
    Verify and decrypt one file chunk
    Returns: plaintext bytes, or None after printing the failure reason
    """
    if len(packet) < 4 + MAC_SIZE:
        print("MALFORMED PACKET")
        return None

    seq_no, mac, encrypted_data = unpack_chunk(packet)

    # Verify MAC on encrypted data
    if mac != compute_mac(encrypted_data, seq_no, session_key):
        print("MAC VERIFICATION FAILED")
        return None

    if seq_no != expected_seq:
        print("OUT OF ORDER PACKET")
        return None

    try:
        decrypted_chunk = aes_decrypt(encrypted_data, aes_key)
    except Exception as e:
        print(f"DECRYPTION FAILED: {e}")
        return None

    print(f"[Cipher]: {encrypted_data[:40].hex()}...")
    print(f"[Plain]: {decrypted_chunk[:40]}")
    return decrypted_chunk

def download_file(client_sock, cmd, filename, aes_key, session_key):
    """
    Send GET and save the file as downloaded_<filename>
    Returns: False if the session must end (connection lost, or a chunk
    failed verification so the stream can no longer be trusted), True otherwise
    """
    send_frame(client_sock, aes_encrypt(cmd, aes_key))

    # Read the first frame exactly once: it is either an error message,
    # the first file chunk, or the empty EOF frame of an empty file
    packet = recv_frame(client_sock)
    if packet is None:
        print("Connection lost.")
        print(f"[CLIENT] DOWNLOAD FAILED: {filename} not received, ending session")
        return False

    # If it's a small packet, it might be an error message. Error replies are
    # IV + ciphertext (a multiple of 16 bytes); chunk frames carry a 36-byte
    # SEQ|MAC header, so they fail to decrypt here and fall through.
    if len(packet) < 100:
        try:
            error_msg = aes_decrypt(packet, aes_key).decode('utf-8')
            if "ERROR" in error_msg or "NOT AVAILABLE" in error_msg:
                print(f"[OUTPUT] {error_msg}")
                return True
        except:
            pass

    expected_seq = 0
    base_filename = "downloaded_" + filename

    if os.path.exists(base_filename):
        choice = input("File exists. Download another copy? (y/n): ").strip().lower()
        if choice != 'y':
            print("Download cancelled.")
            # Discard incoming packets up to the EOF frame
            while packet:
                packet = recv_frame(client_sock)
            return True

        final_filename = get_available_filename(base_filename)
    else:
        final_filename = base_filename

    # Write to a temporary file; it only gets the final name once every
    # chunk has verified and the EOF frame has arrived
    part_filename = final_filename + ".part"
    complete = False
    try:
        with open(part_filename, "wb") as f:
            while True:
                if packet == b'':  # EOF frame
                    complete = True
                    break
                decrypted_chunk = receive_chunk(packet, expected_seq, aes_key, session_key)
                if decrypted_chunk is None:
                    break
                f.write(decrypted_chunk)
                expected_seq += 1

                packet = recv_frame(client_sock)
                if packet is None:
                    print("Connection lost.")
                    break
    finally:
        # Also runs on exceptions (connection reset, Ctrl+C, disk errors)
        if not complete:
            os.remove(part_filename)

    if not complete:
        print(f"[CLIENT] DOWNLOAD FAILED: {filename} discarded, ending session")
        return False

    os.replace(part_filename, final_filename)
    print(f"[CLIENT] File downloaded successfully as {final_filename}")
    return True

#  MAIN CLIENT

def run_client():
    """Main client program with encryption"""
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        print(f"[CLIENT] Connecting to {SERVER_IP}:{SERVER_PORT}...")
        client_sock.connect((SERVER_IP, SERVER_PORT))
        print("[CLIENT] Connected!")

        user_name = input("Username: ").strip()
        secret_key = input("Shared Secret: ").strip()

        # Phase 1: Authentication (plaintext)
        max_tries = 3
        for attempt_num in range(max_tries):
            if perform_login(client_sock, user_name, secret_key):
                break

            if attempt_num < max_tries - 1:
                user_name = input("\nUsername: ").strip()
                secret_key = input("Shared Secret: ").strip()
        else:
            print("[CLIENT] Maximum authentication attempts reached")
            return

        # Phase 2: Diffie-Hellman key exchange (plaintext)
        session_key = establish_shared_key(client_sock)

        if not session_key:
            print("[CLIENT] Failed to establish session key")
            return

        print("[CLIENT] Secure session established.")

        # Phase 3: Derive AES key
        aes_key = derive_aes_key(session_key)
        print("[CLIENT] Encryption enabled. You can now send commands.\n")

        # Phase 4: Encrypted Command Loop
        while True:
            cmd = input("[INPUT] ").strip()

            if not cmd:
                continue

            cmd_parts = cmd.split()
            cmd_upper = cmd_parts[0].upper()

            if cmd_upper == "GET":
                if len(cmd_parts) < 2:
                    print("ERROR: GET requires filename")
                    continue
                if not download_file(client_sock, cmd, cmd_parts[1], aes_key, session_key):
                    break
                continue

            # QUIT, LIST, INFO, GETSIZE: one encrypted request, one encrypted response
            send_frame(client_sock, aes_encrypt(cmd, aes_key))
            encrypted_response = recv_frame(client_sock)

            if cmd_upper == "QUIT":
                if encrypted_response:
                    response = aes_decrypt(encrypted_response, aes_key).decode('utf-8')
                    print(f"[OUTPUT] RESPONSE: {response}")
                break

            if not encrypted_response:
                print("Connection lost.")
                break

            try:
                response = aes_decrypt(encrypted_response, aes_key).decode('utf-8')
                print(f"[OUTPUT] RESPONSE: {response}")
            except Exception as e:
                print(f"Decryption error: {e}")
                break

    except Exception as err:
        print(f"[CLIENT] Error: {err}")

    finally:
        client_sock.close()
        print("[CLIENT] Disconnected")

# ENTRY POINT
if __name__ == '__main__':
    run_client()
