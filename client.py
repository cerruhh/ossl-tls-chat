#!/usr/bin/env python3
"""
Simple TLS client that:
- Reads token from ./auth.key by default (or use --token)
- Connects to server on port 8012 (hostname arg)
- Sends AUTH_TOKEN (single line), then USERNAME (single line), then reads banner/welcome and allows typing Unicode messages.
- Prints messages received from server.
Note: For self-signed server certs, this client by default does NOT verify the server certificate.
If you want verification, pass --cafile <path to server.crt>
"""
import asyncio
import ssl
import argparse
from pathlib import Path

AUTH_KEY = Path("./auth.key")
DEFAULT_PORT = 8012


async def tcp_client(host: str, port: int, token: str, username: str, cafile: str | None):
    if cafile:
        sslctx = ssl.create_default_context(cafile=cafile)
    else:
        sslctx = ssl.create_default_context()
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.open_connection(host, port, ssl=sslctx)
    # send auth token and username, each as a line
    writer.write((token.strip() + "\n").encode("utf-8"))
    writer.write((username.strip() + "\n").encode("utf-8"))
    await writer.drain()

    async def read_task():
        try:
            while True:
                data = await reader.readline()
                if not data:
                    print("Connection closed by server.")
                    break
                try:
                    text = data.decode("utf-8").rstrip("\n\r")
                except Exception:
                    text = "<invalid utf-8>"
                print(text)
        except Exception as e:
            print("Read error:", e)

    async def write_task():
        loop = asyncio.get_running_loop()
        try:
            while True:
                # Read from stdin without blocking other tasks
                line = await loop.run_in_executor(None, input)
                writer.write((line + "\n").encode("utf-8"))
                await writer.drain()
        except EOFError:
            pass
        except Exception as e:
            print("Write error:", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    await asyncio.gather(read_task(), write_task())


def main():
    p = argparse.ArgumentParser(description="Simple TLS chat client (Unicode).")
    p.add_argument("host", help="server hostname or IP (connects on port 8012 by default)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--username", "-u", default="pyclient")
    p.add_argument("--token", "-t", default=None, help="auth token (default: read ./auth.key)")
    p.add_argument("--cafile", help="CA file / server certificate to verify (optional)")
    args = p.parse_args()

    token = args.token
    if not token:
        if AUTH_KEY.exists():
            token = AUTH_KEY.read_text(encoding="utf-8").strip()
        else:
            print("No auth token provided and ./auth.key not found.")
            return

    try:
        asyncio.run(tcp_client(args.host, args.port, token, args.username, args.cafile))
    except KeyboardInterrupt:
        print("Client exiting.")


if __name__ == "__main__":
    main()

