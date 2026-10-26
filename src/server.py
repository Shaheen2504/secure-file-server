"""
Secure Multi-Client File Server
Challenge-response authentication, Diffie-Hellman key exchange,
AES-encrypted commands and MAC-protected chunked file download.
"""

import logging
import os
import secrets
import socket
import threading
from datetime import datetime

from auth import read_user_credentials, verify_user_identity
from crypto_utils import aes_decrypt, aes_encrypt, compute_mac, derive_aes_key, derive_session_key
from protocol import pack_chunk, recv_frame, send_frame

#  CONFIGURATION
SERVER_IP = '127.0.0.1'
SERVER_PORT = 65432
FILES_FOLDER = './files'
LOG_FILENAME = 'server.log'
USERS_FILE = 'config/credentials.txt'
CHUNK_SIZE = 1024

log = logging.getLogger("fileserver")

#  DIFFIE-HELLMAN

def perform_key_exchange(conn):
    """
    Server-side Diffie-Hellman key exchange
    Returns: shared session key (32 bytes)
    """
    try:
        # Step 1: Get DH parameters from client
        params_data = conn.recv(1024).decode('utf-8').strip()
        prime_num, base_num = map(int, params_data.split(','))
        log.info(f"DH: Received p={prime_num}, g={base_num}")

        # Step 2: Generate server's secret number
        server_secret = secrets.randbelow(prime_num - 2) + 1

        # Step 3: Calculate server's public value
        server_public = pow(base_num, server_secret, prime_num)

        # Step 4: Send server public value to client
        conn.sendall(str(server_public).encode('utf-8'))
        log.info(f"DH: Sent server public key B={server_public}")

        # Step 5: Receive client's public value
        client_public = int(conn.recv(1024).decode('utf-8').strip())
        log.info(f"DH: Received client public key A={client_public}")

        # Step 6: Calculate shared secret
        shared_value = pow(client_public, server_secret, prime_num)
        session_key = derive_session_key(shared_value)

        log.info("DH: Session key established")
        return session_key

    except Exception as err:
        log.info(f"DH: Error during key exchange: {err}")
        return None

#  FILE OPERATIONS

def resolve_file(filename):
    """
    Map a client-supplied name to a regular file directly inside FILES_FOLDER
    Returns: real path, or None for '..', absolute paths, symlinks that
    leave the folder, directories and missing files
    """
    base = os.path.realpath(FILES_FOLDER)
    try:
        path = os.path.realpath(os.path.join(base, filename))
    except ValueError:  # embedded NUL byte
        return None
    if os.path.dirname(path) != base or not os.path.isfile(path):
        return None
    return path

def get_file_list():
    """Handle LIST command"""
    try:
        all_items = os.listdir(FILES_FOLDER)
        files_only = [item for item in all_items if os.path.isfile(os.path.join(FILES_FOLDER, item))]
        return ' '.join(files_only) if files_only else "No files found"
    except Exception as err:
        return f"ERROR: {str(err)}"

def get_file_details(filename):
    """Handle INFO command"""
    try:
        file_path = resolve_file(filename)
        if not file_path:
            return "ERROR: File not found"

        file_stats = os.stat(file_path)
        time_created = datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        time_modified = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        file_perms = oct(file_stats.st_mode)[-3:]

        return f"Created: {time_created}, Modified: {time_modified}, Permissions: {file_perms}"
    except Exception as err:
        return f"ERROR: {str(err)}"

def get_file_bytes(filename):
    """Handle GETSIZE command"""
    try:
        file_path = resolve_file(filename)
        if not file_path:
            return "ERROR: File not found"

        return f"{os.path.getsize(file_path)} bytes"
    except Exception as err:
        return f"ERROR: {str(err)}"

def send_file(conn, filename, aes_key, session_key):
    """Handle GET command: send file as encrypted, MAC-protected chunks"""
    filepath = resolve_file(filename)

    if not filepath:
        send_frame(conn, aes_encrypt("FILE NOT AVAILABLE", aes_key))
        return

    seq = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            # Encrypt-then-MAC
            encrypted_chunk = aes_encrypt(chunk, aes_key)
            mac = compute_mac(encrypted_chunk, seq, session_key)
            send_frame(conn, pack_chunk(seq, mac, encrypted_chunk))
            seq += 1

    # EOF marker (0-length frame)
    send_frame(conn, b'')
    log.info(f"RESPONSE: Encrypted file transfer completed for {filename}")

#  COMMAND PROCESSING

def handle_command(cmd_string):
    """Process incoming command and generate response"""
    original_cmd = cmd_string.strip()
    log.info(f"REQUEST: {original_cmd}")

    cmd_parts = original_cmd.split()

    if not cmd_parts:
        result = "ERROR: Empty command"
        log.info(f"RESPONSE: {result}")
        return result

    command = cmd_parts[0].upper()
    args = cmd_parts[1:]

    if command == 'LIST':
        result = get_file_list()
    elif command == 'INFO':
        result = get_file_details(args[0]) if args else "ERROR: INFO requires filename"
    elif command == 'GETSIZE':
        result = get_file_bytes(args[0]) if args else "ERROR: GETSIZE requires filename"
    elif command == 'QUIT':
        result = "GOODBYE"
    else:
        result = "ERROR: Unknown command"

    log.info(f"RESPONSE: {result}")
    return result

#  CLIENT HANDLER

def process_client_connection(client_conn, client_addr, user_db):
    """Handle individual client in separate thread"""
    worker_id = threading.get_ident()
    log.info(f"[Thread {worker_id}] New connection from {client_addr}")

    try:
        # Phase 1: User Authentication (plaintext)
        auth_result, username = verify_user_identity(client_conn, user_db)

        if not auth_result:
            log.info(f"[Thread {worker_id}] Authentication failed for {client_addr}")
            return

        log.info(f"[Thread {worker_id}] User {username} authenticated successfully")

        # Phase 2: Establish Session Key (plaintext)
        session_key = perform_key_exchange(client_conn)

        if not session_key:
            log.info(f"[Thread {worker_id}] Key exchange failed for {username}")
            return

        log.info(f"[Thread {worker_id}] Session established for {username}")

        # Phase 3: Derive AES key from session key
        aes_key = derive_aes_key(session_key)
        log.info(f"[Thread {worker_id}] AES encryption enabled")

        # Phase 4: Encrypted Command Processing Loop
        while True:
            encrypted_cmd = recv_frame(client_conn)
            if not encrypted_cmd:
                break

            try:
                command = aes_decrypt(encrypted_cmd, aes_key).decode('utf-8').strip()
            except Exception as e:
                log.info(f"[Thread {worker_id}] Decryption error: {e}")
                break

            cmd_parts = command.split()
            cmd_upper = cmd_parts[0].upper() if cmd_parts else ""

            if cmd_upper == 'QUIT':
                send_frame(client_conn, aes_encrypt("GOODBYE", aes_key))
                log.info(f"[Thread {worker_id}] Client quit")
                break

            if cmd_upper == 'GET':
                log.info(f"REQUEST: {command}")
                if len(cmd_parts) < 2:
                    send_frame(client_conn, aes_encrypt("ERROR: GET requires filename", aes_key))
                else:
                    send_file(client_conn, cmd_parts[1], aes_key, session_key)
                continue

            # Other commands (LIST, INFO, GETSIZE)
            send_frame(client_conn, aes_encrypt(handle_command(command), aes_key))

    except Exception as err:
        log.info(f"[Thread {worker_id}] Error: {err}")

    finally:
        client_conn.close()
        log.info(f"[Thread {worker_id}] Connection closed with {client_addr}")

#  MAIN SERVER

def start_server():
    """Initialize and run the server"""
    logging.basicConfig(filename=LOG_FILENAME, level=logging.INFO,
                        format='%(asctime)s %(message)s', datefmt='[%Y-%m-%d %H:%M:%S]')

    if not os.path.exists(FILES_FOLDER):
        os.makedirs(FILES_FOLDER)
        print(f"[SERVER] Created directory: {FILES_FOLDER}")

    user_db = read_user_credentials(USERS_FILE)
    print(f"[SERVER] Loaded {len(user_db)} user credentials")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((SERVER_IP, SERVER_PORT))
    server_sock.listen(5)

    print(f"[SERVER] Listening on {SERVER_IP}:{SERVER_PORT}")
    log.info("[SERVER] Server started")

    try:
        while True:
            print("[SERVER] Waiting for connection...")
            client_conn, client_addr = server_sock.accept()

            # One thread per client
            worker_thread = threading.Thread(
                target=process_client_connection,
                args=(client_conn, client_addr, user_db),
                daemon=True,
            )
            worker_thread.start()
            print(f"[SERVER] Started thread for {client_addr}")

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down...")

    finally:
        server_sock.close()
        log.info("[SERVER] Server stopped")

#  ENTRY POINT
if __name__ == '__main__':
    start_server()
