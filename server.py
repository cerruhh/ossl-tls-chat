#!/usr/bin/env python3
"""
Server program:
- Generates a self-signed cert and private key if missing, writes private key to ./server.key
  and certificate to ./server.crt
- Generates ./auth.key if missing (32-byte hex token)
- Listens on port 8012 with TLS
- Expects first line from client: AUTH_TOKEN
  second line: USERNAME
- Sends banner text (./banner.txt) upon successful auth/username if file exists
- Broadcasts Unicode messages from clients to all others WITHOUT revealing IP addresses
"""
import asyncio
import ssl
import os
import secrets
from pathlib import Path
from typing import Dict, Set, Tuple

# We'll use cryptography to create a self-signed certificate if needed.
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
except Exception:
    raise SystemExit(
        "This server requires the 'cryptography' package. Install with:\n\n"
        "    pip install cryptography\n"
    )

SERVER_KEY = Path("./server.key")
SERVER_CRT = Path("./server.crt")
AUTH_KEY = Path("./auth.key")
BANNER = Path("./banner.txt")
HOST = "0.0.0.0"
PORT = 8012

# In-memory client bookkeeping
# writer -> username
clients: Dict[asyncio.StreamWriter, str] = {}
clients_lock = asyncio.Lock()


from datetime import datetime, timedelta

def make_self_signed_cert(key_path: Path, crt_path: Path):
    """Generate a self-signed cert and key and write to files."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    # Write key
    with key_path.open("wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Write cert
    with crt_path.open("wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated self-signed key -> {key_path} and cert -> {crt_path}")


def ensure_keys_and_auth():
    if not (SERVER_KEY.exists() and SERVER_CRT.exists()):
        print("server.key or server.crt missing — generating self-signed certificate...")
        make_self_signed_cert(SERVER_KEY, SERVER_CRT)
    else:
        print("Found existing server.key and server.crt")

    if not AUTH_KEY.exists():
        token = secrets.token_hex(32)
        AUTH_KEY.write_text(token, encoding="utf-8")
        os.chmod(AUTH_KEY, 0o600)
        print(f"Generated auth token -> {AUTH_KEY} (use this in your clients)")
    else:
        print(f"Found existing auth key -> {AUTH_KEY}")

    if BANNER.exists():
        print(f"Banner found at {BANNER}")
    else:
        print("No banner file at ./banner.txt (optional)")


async def broadcast_message(from_user: str, message: str, exclude_writer: asyncio.StreamWriter = None):
    """Broadcast message to all connected clients except exclude_writer."""
    text = f"{from_user}: {message}\n"
    data = text.encode("utf-8")
    async with clients_lock:
        to_remove = []
        for w in list(clients.keys()):
            if w is exclude_writer:
                continue
            try:
                w.write(data)
                await w.drain()
            except Exception:
                to_remove.append(w)
        for w in to_remove:
            await remove_client(w)


async def remove_client(writer: asyncio.StreamWriter):
    """Cleanup a disconnected client."""
    async with clients_lock:
        uname = clients.pop(writer, None)
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    if uname:
        # notify others user left
        await broadcast_message("SERVER", f"{uname} has left.")


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")  # we will not share this with others
    # Step 1: read auth token line
    try:
        auth_line = (await reader.readline()).decode("utf-8").rstrip("\n\r")
        if not auth_line:
            writer.close()
            await writer.wait_closed()
            return
    except Exception:
        writer.close()
        await writer.wait_closed()
        return

    expected = AUTH_KEY.read_text(encoding="utf-8").strip()
    if auth_line != expected:
        writer.write("AUTH_FAIL\n".encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print(f"Rejected connection from {peer} due to bad auth token.")
        return

    # Step 2: read username
    try:
        username = (await reader.readline()).decode("utf-8").strip()
        if not username:
            username = "anonymous"
    except Exception:
        writer.close()
        await writer.wait_closed()
        return

    # Add to clients
    async with clients_lock:
        clients[writer] = username

    print(f"Authenticated user '{username}' from connection {peer} (peer hidden from others).")
    # Send banner if exists
    if BANNER.exists():
        banner_text = BANNER.read_text(encoding="utf-8")
        try:
            writer.write(banner_text.encode("utf-8") + b"\n")
            await writer.drain()
        except Exception:
            await remove_client(writer)
            return

    # Notify others (but not IP)
    await broadcast_message("SERVER", f"{username} has joined.", exclude_writer=writer)
    # Optionally welcome the user
    try:
        writer.write(f"Welcome, {username}!\n".encode("utf-8"))
        await writer.drain()
    except Exception:
        await remove_client(writer)
        return

    # Main loop: read messages and broadcast
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                text = line.decode("utf-8").rstrip("\n\r")
            except Exception:
                text = "<invalid utf-8 data>"
            # Do not include peer info anywhere
            await broadcast_message(username, text, exclude_writer=None)
    except Exception:
        pass
    finally:
        await remove_client(writer)


async def main():
    ensure_keys_and_auth()

    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Use server.crt and server.key (server.key created as PEM private key)
    sslctx.load_cert_chain(certfile=str(SERVER_CRT), keyfile=str(SERVER_KEY))

    server = await asyncio.start_server(handle_client, HOST, PORT, ssl=sslctx)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Server running on {addrs} (TLS, port {PORT}).")
    print("Clients must send a single-line auth token, then a single-line username, then messages (UTF-8).")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server shutting down.")

