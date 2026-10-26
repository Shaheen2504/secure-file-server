# Secure File Transfer System

A TCP file server and command-line client in Python. Clients log in with a challenge-response protocol, agree on a session key with Diffie-Hellman, and then exchange commands, responses and files encrypted with AES-128-CBC. Downloads are sent in numbered chunks, each with a MAC, and the client only keeps a file once every chunk has been verified.

This is an educational implementation. It shows how these mechanisms fit together, and it has known weaknesses that are listed under [Security limitations](#security-limitations). It is not meant for protecting real data.

## What it does

The server shares the files in its `files/` directory. Several clients can be connected at once; each one is handled in its own thread. After logging in, a client can:

| Command | Result |
|---|---|
| `LIST` | List the files in `files/` |
| `INFO <file>` | Show created and modified times and permission bits |
| `GETSIZE <file>` | Show the size in bytes |
| `GET <file>` | Download the file, saved as `downloaded_<file>` |
| `QUIT` | Close the session |

Command words are case-insensitive. Only regular files directly inside `files/` can be read. Paths that use `..` to leave the folder, absolute paths, directories and symlinks that point outside the folder are rejected.

## Features

- TCP client-server communication using the standard `socket` module
- One thread per client, so several clients can connect at the same time
- Challenge-response login: the client proves it knows the shared secret by hashing it with a random server nonce, so the secret itself is never sent. After 3 wrong secrets for a user, counted across connections, the account is locked until the server restarts.
- Diffie-Hellman key exchange, giving each connection its own session key
- AES-128-CBC encryption with a random IV for every message after the key exchange
- Length-prefixed message framing, so messages survive TCP splitting or merging them
- Chunked downloads (1024-byte chunks), each with a sequence number and a MAC computed over the ciphertext
- Download verification: a file is written to `<name>.part` and only renamed once every chunk has passed its checks and the end-of-file marker has arrived. On a MAC failure, an out-of-order chunk or a lost connection, the partial file is deleted and the session ends.
- File-name validation on the server for `INFO`, `GETSIZE` and `GET`
- Server log (`server.log`) of logins, requests and responses, without secrets or key material

## How it works

```
 Client                                              Server (one thread per client)
   |  1. Login (plaintext)                              |
   |---- username ------------------------------------->|
   |<--- nonce ------------------------------------------|
   |---- SHA256(nonce || shared_secret) --------------->|
   |<--- AUTH_SUCCESS | AUTH_FAILED:n | ACCOUNT_LOCKED --|
   |                                                    |
   |  2. Diffie-Hellman (plaintext)                     |
   |---- p,g ------------------------------------------->|
   |<--- B = g^b mod p ----------------------------------|
   |---- A = g^a mod p --------------------------------->|
   |  session_key = SHA256(g^ab mod p), AES key = first 16 bytes
   |                                                    |
   |  3. Encrypted session, every message: [length | IV | AES-CBC ciphertext]
   |==== LIST / INFO / GETSIZE / QUIT =================>|
   |<=== response =======================================|
   |==== GET <file> ====================================>|
   |<=== [length | seq | MAC | AES-CBC(chunk 0)] ========|  MAC = SHA256(ciphertext || seq || session_key)
   |<=== [length | seq | MAC | AES-CBC(chunk 1)] ========|
   |<=== [length = 0]  end of file ======================|
```

The client checks each chunk in this order: MAC, sequence number, then decryption. [docs/design.md](docs/design.md) has the full message formats and the reasoning behind them.

## Repository structure

```
src/
  server.py         accept loop, per-client handler, server side of DH, file commands
  client.py         interactive client: login, DH, encrypted commands, verified download
  auth.py           credential loading, challenge-response check, account lockout
  crypto_utils.py   challenge hash, session key derivation, MAC, AES-CBC helpers
  protocol.py       exact reads, length-prefixed frames, chunk layout
tests/              unittest suite (no network port needed)
config/
  credentials.example.txt   example user list; copy it to credentials.txt
files/              small sample files served by the server
docs/design.md      protocol details, design decisions and known weaknesses
```

## Requirements

- Python 3 (tested with Python 3.14 on Linux)
- [pycryptodome](https://pypi.org/project/pycryptodome/) for AES (see `requirements.txt`)

## Setup and running

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp config/credentials.example.txt config/credentials.txt
```

Edit `config/credentials.txt` and replace the example secrets with your own test values. Each line is `username:shared_secret`. The file is gitignored. Don't use passwords you use anywhere else; the secrets are stored in plain text.

Run both programs from the repository root:

```bash
# Terminal 1
python3 src/server.py          # listens on 127.0.0.1:65432, logs to server.log

# Terminal 2
python3 src/client.py          # prompts for username and shared secret
```

The client reads the Diffie-Hellman parameters from the `P` and `G` environment variables and sends them to the server. If they are not set it uses `p = 23, g = 5`. These defaults are for demonstration only. Any prime can be used, for example:

```bash
P=170141183460469231731687303715884105727 G=3 python3 src/client.py   # p = 2^127 - 1
```

That is still far below the size needed for real security.

A short session with the sample files:

```
[CLIENT] Authentication successful!
[CLIENT] Session key established
[CLIENT] Encryption enabled. You can now send commands.

[INPUT] LIST
[OUTPUT] RESPONSE: file1.txt sample.txt data.txt file2.txt
[INPUT] GETSIZE sample.txt
[OUTPUT] RESPONSE: 44 bytes
[INPUT] GET file1.txt
[Cipher]: f68a26203199fdce155b6362855636fbf1c14b42c7375869f9c6a29b2e105d0c...
[Plain]: b'Hello World\n'
[CLIENT] File downloaded successfully as downloaded_file1.txt
[INPUT] GET ../config/credentials.txt
[OUTPUT] FILE NOT AVAILABLE
[INPUT] QUIT
[OUTPUT] RESPONSE: GOODBYE
```

## Running the tests

The tests use the standard `unittest` module. They run the real server handler and client functions over in-process socket pairs, so no server needs to be running. Install the requirements first.

```bash
python3 -m unittest discover -s tests -v
```

| File | What it checks |
|---|---|
| `test_auth.py` | Login success and failure, unknown users, lockout (including across connections), reset after a successful login, credential parsing |
| `test_crypto.py` | AES round trips, random IVs, wrong key, MAC sensitivity to data, sequence number and key |
| `test_protocol.py` | Exact reads with fragmented input, frame round trips, chunk layout |
| `test_server.py` | Encrypted `LIST`, `INFO`, `GETSIZE`, `QUIT` and a multi-chunk download |
| `test_path_traversal.py` | `..`, absolute paths, symlinks, directories and NUL bytes rejected |
| `test_download.py` | Files from 0 to 1025 bytes download intact; cancel and numbered-copy paths |
| `test_download_integrity.py` | Tampered, reordered, replayed and malformed chunks; connections that drop or reset mid-transfer |
| `test_logging.py` | The server log does not reveal the session key |

One test, `test_dropped_final_chunk_is_detected`, is marked as an expected failure. It documents limitation 4 below. If an attacker drops the last chunk of a download, the client still reports success.

## Security limitations

The design is not secure against an active network attacker. The main problems, in order of importance:

1. **Unauthenticated Diffie-Hellman.** The key exchange is not tied to the login, so a man-in-the-middle can run a separate exchange with each side and read or change all traffic.
2. **Weak, client-chosen DH parameters.** The default `p = 23` allows only 22 possible keys. The server accepts any `p` and `g` the client sends, and does not check the public values (sending `A = 1` forces the shared value to 1).
3. **Custom MAC.** File chunks use `SHA256(ciphertext || seq || key)` instead of HMAC, and the tag is compared with `!=` rather than in constant time.
4. **Incomplete integrity protection.** Only file chunks carry a MAC. Commands and responses are AES-CBC encrypted but not authenticated, so they can be modified undetectably. The end-of-file marker is not authenticated either. An attacker who drops the final chunks of a download lets the server's real end-of-file marker through, and the client saves the shortened file as a successful download. Chunks dropped from the middle are detected by the sequence check. Sequence numbers restart at 0 for every file.
5. **One key for encryption and the MAC.** The AES key is the first 16 bytes of the session key, and the MAC uses the whole session key.
6. **Shared secrets and login.** Secrets are stored in plain text on the server. Anyone who captures a nonce and its response can test password guesses offline. The `INVALID_USER` reply reveals which usernames exist. The response hash is compared with `==`, not in constant time. Anyone can lock any account by sending three wrong secrets, and the lock lasts until the server restarts.
7. **Unframed handshake.** Login and key-exchange messages are read with plain `recv(1024)` calls. If two messages arrive together they are read as one, so the lockout notice can be merged with the previous reply, and a command sent immediately after the client's DH value can break the exchange.
8. **No size limits or configuration.** Frames have no maximum size, logged requests are not sanitised, and the host, port and paths are constants in the source.

Fixing items 1 to 7 needs a protocol change rather than small patches. The likely direction:
- a standard 2048-bit DH group or X25519, with an authenticated key exchange
- separate keys derived with HKDF
- AES-GCM for every message, including an authenticated end-of-file frame
- length-prefixed framing from the very first message
- salted, hashed credentials

## Background

This started as a two-person university project. I wrote the authentication, multi-client threading, Diffie-Hellman key exchange and AES encryption. My teammate wrote the original file commands, the chunked transfer and the chunk MAC. We tested and debugged it together.

I later reorganised the code into modules and added the test suite. I also fixed several bugs, each with a regression test:
- path traversal
- a download hang on small files
- the DH shared secret appearing in the log
- failed downloads being reported as successful
- a lockout bypass by reconnecting

The commit history shows these changes.
