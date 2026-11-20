#!/usr/bin/env python3
"""Minimal authenticated TCP relay server.

Written from scratch, stdlib only. Listens on PORT (default 1080).
Also answers plain HTTP GET /health on the same port so a platform
health check can confirm the process is alive.
"""
import asyncio
import ipaddress
import logging
import os
import socket
import struct
import time

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "info").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("relay")

USERNAME = os.environ.get("RELAY_USERNAME", "relayuser")
PASSWORD = os.environ.get("RELAY_PASSWORD", "")
PORT = int(os.environ.get("PORT", "1080"))

# Rate limit: >10 failed logins from one IP in 60s -> block it for 300s.
_failed = {}
_blocked_until = {}


def _blocked(ip):
    until = _blocked_until.get(ip, 0)
    if until and time.time() < until:
        return True
    if until:
        del _blocked_until[ip]
    return False


def _record_fail(ip):
    now = time.time()
    recent = [t for t in _failed.get(ip, []) if now - t < 60]
    recent.append(now)
    _failed[ip] = recent
    if len(recent) >= 10:
        _blocked_until[ip] = now + 300
        _failed[ip] = []
        log.warning("blocking %s for 5m after 10 failed logins", ip)


async def _read_exact(reader, n):
    data = await reader.readexactly(n)
    return data


async def _pipe(reader, writer):
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _handle_health(reader, writer, first):
    """First bytes looked like HTTP: answer GET /health, else 404."""
    try:
        rest = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    except Exception:
        return
    line = (first + rest).split(b"\r\n", 1)[0].decode("latin1", "ignore")
    parts = line.split(" ")
    path = parts[1] if len(parts) > 1 else "/"
    body = b"ok" if path == "/health" else b"not found"
    code = b"200 OK" if path == "/health" else b"404 Not Found"
    writer.write(b"HTTP/1.1 " + code + b"\r\nContent-Length: " + str(len(body)).encode() +
                 b"\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n" + body)
    await writer.drain()


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername") or ("?", 0)
    ip = peer[0]
    if _blocked(ip):
        log.warning("refusing blocked ip %s", ip)
        writer.close()
        return
    try:
        first = await _read_exact(reader, 1)
    except Exception:
        writer.close()
        return
    # HTTP health check on the same port.
    if first in (b"G", b"H", b"P", b"D", b"O"):
        await _handle_health(reader, writer, first)
        writer.close()
        return
    if first != b"\x05":
        writer.close()
        return
    try:
        nmethods = (await _read_exact(reader, 1))[0]
        methods = await _read_exact(reader, nmethods)
    except Exception:
        writer.close()
        return
    if 0x02 in methods:
        writer.write(b"\x05\x02")  # username/password auth (required)
    else:
        writer.write(b"\x05\xff")  # no acceptable methods
        await writer.drain()
        writer.close()
        return
    await writer.drain()

    authed = True
    if 0x02 in methods:
        authed = False
        try:
            ver = await _read_exact(reader, 1)
            if ver != b"\x01":
                raise ValueError("bad auth version")
            ulen = (await _read_exact(reader, 1))[0]
            user = (await _read_exact(reader, ulen)).decode("utf-8", "ignore")
            plen = (await _read_exact(reader, 1))[0]
            pw = (await _read_exact(reader, plen)).decode("utf-8", "ignore")
        except Exception:
            writer.close()
            return
        if user == USERNAME and pw == PASSWORD:
            authed = True
            writer.write(b"\x01\x00")
        else:
            _record_fail(ip)
            log.warning("failed login for %s from %s", user, ip)
            writer.write(b"\x01\x01")
        await writer.drain()
    if not authed:
        writer.close()
        return

    try:
        ver, cmd, _, atyp = struct.unpack("!BBBB", await _read_exact(reader, 4))
    except Exception:
        writer.close()
        return
    if ver != 0x05 or cmd != 0x01:  # only CONNECT
        writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        writer.close()
        return
    try:
        if atyp == 0x01:  # IPv4
            raw = await _read_exact(reader, 4)
            host = socket.inet_ntoa(raw)
            host_bytes = raw
        elif atyp == 0x03:  # domain
            dlen = (await _read_exact(reader, 1))[0]
            host = (await _read_exact(reader, dlen)).decode("utf-8", "ignore")
            host_bytes = bytes([dlen]) + host.encode()
        elif atyp == 0x04:  # IPv6
            raw = await _read_exact(reader, 16)
            host = socket.inet_ntop(socket.AF_INET6, raw)
            host_bytes = raw
        else:
            raise ValueError("bad address type")
        dest_port = struct.unpack("!H", await _read_exact(reader, 2))[0]
    except Exception:
        writer.close()
        return

    try:
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(host, dest_port), timeout=15)
    except Exception as exc:
        log.info("connect %s:%d failed: %s", host, dest_port, exc)
        writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        writer.close()
        return

    local = target_writer.get_extra_info("sockname") or ("0.0.0.0", 0)
    try:
        bind_ip = ipaddress.ip_address(local[0])
        if bind_ip.version == 4:
            reply = b"\x05\x00\x00\x01" + socket.inet_aton(local[0]) + struct.pack("!H", local[1])
        else:
            reply = b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, local[0]) + struct.pack("!H", local[1])
    except Exception:
        reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    writer.write(reply)
    await writer.drain()
    log.info("relay %s -> %s:%d", ip, host, dest_port)
    await asyncio.gather(_pipe(reader, target_writer), _pipe(target_reader, writer))
    writer.close()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", PORT)
    log.info("listening on 0.0.0.0:%d", PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
