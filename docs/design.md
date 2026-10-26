# Design

This document describes the protocol, the design decisions behind it, problems met while building it, and its known weaknesses. The README has the short version and run instructions.

## 1. How the system was built

The features were added incrementally, each building on the previous one:

| Step | Added | Main code today |
|---|---|---|
| File service | TCP client/server; `LIST`, `INFO`, `GETSIZE`, `QUIT`; request/response logging | `server.py` file operations, `handle_command` |
| Authentication and key exchange | One thread per client; challenge-response login; account lockout; Diffie-Hellman session key | `auth.py`, `perform_key_exchange`, `establish_shared_key` |
| File download | `GET` with 1024-byte chunks, sequence numbers and a per-chunk MAC | `send_file`, `download_file`, `protocol.py` |
| Encryption | AES-128-CBC for all traffic after key exchange; length-prefixed frames; MAC over ciphertext | `crypto_utils.py`, encrypted command loop |
| Later fixes | Module split, test suite, bug fixes (section 6) | all |

## 2. Components

```
src/
  server.py        accept loop (thread per client), DH (server side), file commands, GET sender
  client.py        interactive client: login, DH (client side), encrypted commands, GET receiver
  auth.py          credential loading, challenge-response check, in-memory lockout
  crypto_utils.py  SHA-256 challenge response, session key derivation, MAC, AES-128-CBC
  protocol.py      recv_exact, 4-byte length-prefixed frames, SEQ|MAC|DATA chunk layout
```

Shared state on the server is limited to the lockout table (guarded by a lock) and the log (the `logging` module is thread-safe). Each connection is otherwise independent.

## 3. Protocol

### 3.1 Login (plaintext)

```
C -> S   username
S -> C   INVALID_USER | ACCOUNT_LOCKED | nonce (32 hex chars, secrets.token_hex(16))
C -> S   SHA256(nonce || shared_secret)          (64 hex chars)
S -> C   AUTH_SUCCESS | AUTH_FAILED:<attempts left> | ACCOUNT_LOCKED
```

- The secret itself never crosses the network, and a fresh nonce per attempt stops a captured response from being replayed in a later login.
- Wrong secrets are counted per username across all connections, and a successful login resets the count. The third consecutive wrong secret locks the account.
- A single connection also gets at most 3 failed attempts, with unknown usernames counting too. After that the server locks the last username tried and closes the connection.
- Locks and counts live in memory: they last until the server restarts.

### 3.2 Diffie-Hellman (plaintext)

```
C -> S   "p,g"          (read by the client from env vars P and G; default 23, 5)
S -> C   B = g^b mod p
C -> S   A = g^a mod p
both     shared = A^b = B^a mod p
         session_key = SHA256(str(shared))     32 bytes
         aes_key     = session_key[:16]        AES-128
         mac_key     = session_key             (whole key, see limitations)
```

Private exponents come from `secrets.randbelow`, so every connection gets a new session key.

### 3.3 Encrypted session

Every message after key exchange is one frame:

```
LENGTH (4 bytes, big-endian) | IV (16) | AES-128-CBC ciphertext (PKCS#7 padded)
```

`LIST`, `INFO <f>`, `GETSIZE <f>` and `QUIT` are one request frame and one response frame. The length prefix is what makes this work over TCP, which is a byte stream: one `recv()` may return half a message or two messages.

### 3.4 File download

```
C -> S   frame: E("GET <name>")
S -> C   frame: E("FILE NOT AVAILABLE")                          if the name is not a file in files/
     or  frame: SEQ (4) | MAC (32) | E(chunk_0)                  chunk = up to 1024 bytes
         frame: SEQ (4) | MAC (32) | E(chunk_1)
         ...
         frame: empty (LENGTH = 0)                               end of file

MAC = SHA256(E(chunk) || SEQ || session_key)
```

The client checks each chunk in this order: MAC, then sequence number, then decryption. Chunks are written to `downloaded_<name>.part`, and the file is renamed to its final name only after the end-of-file frame arrives with every chunk verified. On any failure the partial file is deleted and the client ends the session.

The client tells an error reply from a file chunk by size. Error replies are `IV + ciphertext`, a multiple of 16 bytes. Chunk frames carry a 36-byte header, so trying to decrypt one as a message always fails.

## 4. Design decisions

| Decision | Reason |
|---|---|
| Challenge-response instead of sending the password | The secret is never transmitted; nonces prevent straightforward replay. |
| Thread per client | Simple model for a small number of concurrent clients; each handler is independent apart from the lockout table and log. |
| Length-prefixed frames | TCP has no message boundaries. Early versions failed with "Padding is incorrect" when a ciphertext arrived split across `recv()` calls. |
| Random IV per message, prepended to the ciphertext | Identical commands encrypt differently, and the receiver gets the IV without separate state. |
| Encrypt-then-MAC for file chunks | The MAC is checked before any decryption, so tampered ciphertext is rejected without being processed. |
| Sequence number inside the MAC | Reordered or duplicated chunks, and chunks dropped from the middle of a transfer, are detected. Dropping the *final* chunks is not detected (section 8, item 5). |
| `.part` file plus rename | A failed or interrupted download never looks like a complete one, and an earlier good copy is never overwritten. |
| End the session after a failed chunk | The rest of the stream can't be trusted or re-synchronised. |

## 5. Problems solved during development

- **Filenames converted to upper case.** The first version upper-cased the whole command, so `INFO file1.txt` looked for `FILE1.TXT`. Fixed by upper-casing only the command word.
- **Interleaved log lines.** With several threads writing to `server.log`, entries got mixed together. Fixed with a lock (now the `logging` module).
- **Lockout during testing.** Locks are in memory on purpose, so a restart clears them. A real deployment would persist them and expire them after a timeout.
- **Message fragmentation.** Encrypted messages split across `recv()` calls failed to decrypt. Fixed with the 4-byte length prefix and `recv_exact`.
- **IV handling.** The receiver needs the random IV; it is sent as the first 16 bytes of each message.
- **Showing encryption works.** Packet captures in Wireshark confirmed that after key exchange, commands, responses and file data are unreadable on the wire, while the login and DH messages remain plaintext. Decrypting with a wrong key was also checked to fail.

## 6. Bugs fixed later

Each fix has a regression test.

| Bug | Root cause | Fix | Test |
|---|---|---|---|
| Path traversal | The filename from the client went straight into `os.path.join(files, name)`. `../x`, absolute paths and symlinks could reach any file the server can read, including the credentials file. | `resolve_file()` uses `realpath` and accepts only regular files directly inside `files/`. | `test_path_traversal.py` |
| `GET` hung on files under 32 bytes | The client read a small first frame to check for an error and then read the same frame length again, consuming the EOF marker and blocking. | Read the first frame once and reuse it. | `test_download.py` |
| DH shared secret in `server.log` | The log line included the shared value, and the session key is its hash. | The value is no longer logged. | `test_logging.py` |
| Failed downloads reported as successful | On MAC, order or connection failure the loop just stopped, kept the partial file and printed "downloaded successfully". | `.part` file, delete it on failure, print `DOWNLOAD FAILED`, end the session. | `test_download_integrity.py` |
| NUL byte in a filename | `realpath()` raises `ValueError` on an embedded NUL, so `INFO`/`GETSIZE` returned the raw error and `GET` dropped the connection. | Treat it as not found. | `test_path_traversal.py` |
| `.part` file left after a reset | A connection reset or Ctrl+C during a download raised an exception that skipped the cleanup. | Delete the partial file in a `finally` block. | `test_download_integrity.py` |
| Lockout bypass | Failures were counted per connection, so making two guesses and reconnecting allowed unlimited guesses. | Count failures per username across connections; reset on success. | `test_auth.py` |

## 7. What an eavesdropper sees

Login and key exchange are plaintext by design: the username, nonce, response hash, `p`, `g`, `A` and `B` are all visible. After that, every command, response and file chunk is ciphertext. The message sizes and timing are still visible.

## 8. Known weaknesses

The scheme demonstrates the building blocks of a secure channel. It is **not** secure against an active attacker.

1. **Unauthenticated Diffie-Hellman.** Nothing ties the DH values to the login, so a man-in-the-middle can run separate exchanges with both sides and read or change everything.
2. **Client-chosen, tiny DH parameters.** The default `p = 23` allows only 22 possible keys. The server accepts any `p, g` the client sends and does not check public values (`A = 1` forces the shared value to 1).
3. **Home-made MAC.** `SHA256(data || seq || key)` instead of HMAC, compared with `!=` instead of a constant-time comparison.
4. **Commands and responses are not authenticated.** Only file chunks carry a MAC. CBC ciphertext of commands can be modified undetectably.
5. **Unauthenticated end of file.** The end-of-file marker is an empty frame with no MAC, and neither the chunk count nor the file size is authenticated. An attacker who drops the final chunk frames in transit does not need to forge anything: every chunk that arrives still verifies with consecutive sequence numbers, the server's genuine end-of-file frame follows, and the client accepts and saves a truncated file as a successful download (recorded as the expected failure `test_dropped_final_chunk_is_detected`). Sequence numbers restart at 0 for every file, so chunks from one transfer could be replayed into another in the same session.
6. **One key for two jobs.** The AES key is the first half of the MAC key, not a separately derived key.
7. **CBC instead of an AEAD mode** such as AES-GCM.
8. **Credentials.** Shared secrets are stored in plaintext. A sniffed nonce plus response lets an attacker test guesses offline. `INVALID_USER` reveals which usernames exist. The response hash is compared with `==`, not in constant time. Anyone can lock any account with three wrong secrets, and the lock lasts until restart.
9. **Unframed handshake.** Login and DH use raw `recv(1024)`. When two messages arrive together they are read as one: the client may see `AUTH_FAILED:0` and `ACCOUNT_LOCKED` merged, and a command sent immediately after the client's DH value can break the exchange. Interactive use hides this; the tests synchronise around it.
10. **No input limits.** Frames have no maximum size: the receiver keeps buffering a frame of up to 4 GB for as long as the peer keeps sending.
11. **Log injection.** Requests are logged as received, so a crafted command containing a newline can add fake lines to `server.log`.
12. **Hard-coded configuration.** Host, port, paths and limits are constants in the source.

Fixing items 1-10 means changing the wire protocol: HMAC, a standard 2048-bit group with validation or X25519, an authenticated key exchange, HKDF, AES-GCM with an authenticated final frame, framing from the first message, length limits and hashed credentials. Old and new clients would not interoperate.
