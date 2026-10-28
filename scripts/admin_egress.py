#!/usr/bin/env python3
"""Fixed-destination SOCKS5 TCP bridge. Stdlib only; no credentials or logging.

The caller must bind an explicit address on the internal Docker interface. TLS
and admin authentication remain end-to-end between the agent and fixed origin.
"""
import argparse
import asyncio
from dataclasses import dataclass
import ipaddress
import math
import re
import signal
import socket


BUFFER = 65536
SUCCESS = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
DENIED = b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00"
FAILED = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"


@dataclass(frozen=True, repr=False)
class Config:
    bind_ip: str
    allowed_host: str
    port: int = 1080
    upstream_host: str | None = None
    upstream_port: int | None = None
    max_sessions: int = 16
    handshake_timeout: float = 10
    idle_timeout: float = 120
    write_timeout: float = 10
    close_timeout: float = 1

    def __post_init__(self):
        address = ipaddress.ip_address(self.bind_ip)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("explicit unicast bind address required")
        # Canonical ASCII DNS name only; no URL, IDNA conversion, trailing dot,
        # wildcard, literal IP, or alternate spelling accepted on the wire.
        host = self.allowed_host
        if (not isinstance(host, str) or not 1 <= len(host) <= 253 or
                host != host.lower() or "." not in host or
                any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in host.split("."))):
            raise ValueError("canonical DNS hostname required")
        try:
            # Unlike ip_address, inet_aton also catches abbreviated, octal,
            # and hexadecimal IPv4 spellings that libc resolves without DNS.
            socket.inet_aton(host)
        except OSError:
            pass
        else:
            raise ValueError("IP destination forbidden")
        if not 0 <= self.port <= 65535 or not 8 <= self.max_sessions <= 256:
            raise ValueError("invalid listener bounds")
        if (self.upstream_host is None) != (self.upstream_port is None):
            raise ValueError("upstream host and port must be paired")
        if self.upstream_host is not None:
            # Fixed no-auth SOCKS endpoint, not a URL containing credentials.
            if (not self.upstream_host or len(self.upstream_host) > 253 or
                    not re.fullmatch(r"[a-zA-Z0-9.:-]+", self.upstream_host) or
                    not 1 <= self.upstream_port <= 65535):
                raise ValueError("invalid upstream endpoint")
        if any(not math.isfinite(t) or not 0 < t <= 3600 for t in (
                self.handshake_timeout, self.idle_timeout,
                self.write_timeout, self.close_timeout)):
            raise ValueError("invalid timeout bounds")


class Bridge:
    """One listener, bounded admitted sessions, and deterministic shutdown."""

    def __init__(self, config):
        self.config = config
        self._server = None
        self._sessions = {}

    @property
    def address(self):
        return self._server.sockets[0].getsockname()[:2]

    async def start(self):
        if self._server is not None:
            raise RuntimeError("already started")
        self._server = await asyncio.start_server(
            self._accept, self.config.bind_ip, self.config.port,
            limit=BUFFER, backlog=self.config.max_sessions)

    async def close(self):
        if self._server is not None:
            self._server.close()
        tasks = list(self._sessions)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Newer asyncio versions also wait for active client transports here.
        if self._server is not None:
            await self._server.wait_closed()

    def _accept(self, reader, writer):
        # Synchronous admission: never spawn unbounded tasks waiting for slots.
        if (self._server is None or not self._server.is_serving() or
                len(self._sessions) >= self.config.max_sessions):
            writer.transport.abort()
            return
        task = asyncio.create_task(self._handle(reader, writer))
        self._sessions[task] = writer
        task.add_done_callback(self._finished)

    def _finished(self, task):
        # Covers cancellation before the session coroutine gets its first turn.
        writer = self._sessions.pop(task)
        writer.transport.abort()
        if not task.cancelled():
            task.exception()  # Consume errors without exposing endpoint/body data.

    async def _write(self, writer, data):
        writer.write(data)
        await asyncio.wait_for(writer.drain(), self.config.write_timeout)

    async def _close_writer(self, writer):
        if writer is None:
            return
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), self.config.close_timeout)
        except (OSError, TimeoutError):
            pass
        finally:
            writer.transport.abort()

    async def _request(self, reader, writer):
        version, count = await reader.readexactly(2)
        if version != 5 or count == 0:
            return False
        methods = await reader.readexactly(count)
        if 0 not in methods:
            await self._write(writer, b"\x05\xff")
            return False
        await self._write(writer, b"\x05\x00")
        # Reject CONNECT alternatives and IP ATYP before touching any upstream.
        if await reader.readexactly(4) != b"\x05\x01\x00\x03":
            await self._write(writer, DENIED)
            return False
        length = (await reader.readexactly(1))[0]
        if not length:
            await self._write(writer, DENIED)
            return False
        host = await reader.readexactly(length)
        port = await reader.readexactly(2)
        if host != self.config.allowed_host.encode("ascii") or port != b"\x01\xbb":
            await self._write(writer, DENIED)
            return False
        return True

    async def _open_upstream(self):
        if self.config.upstream_host is None:
            return await asyncio.open_connection(self.config.allowed_host, 443, limit=BUFFER)
        writer = None
        try:
            reader, writer = await asyncio.open_connection(
                self.config.upstream_host, self.config.upstream_port, limit=BUFFER)
            # Same strict no-auth RFC 1928 exchange as Relay.open_upstream;
            # standalone deliberately avoids importing application snapshots.
            await self._write(writer, b"\x05\x01\x00")
            if await reader.readexactly(2) != b"\x05\x00":
                raise ConnectionError()
            host = self.config.allowed_host.encode("ascii")
            await self._write(writer, b"\x05\x01\x00\x03" + bytes([len(host)]) +
                              host + b"\x01\xbb")
            reply = await reader.readexactly(4)
            if reply[:3] != b"\x05\x00\x00":
                raise ConnectionError()
            if reply[3] == 1:
                length = 4
            elif reply[3] == 4:
                length = 16
            elif reply[3] == 3:
                length = (await reader.readexactly(1))[0]
                if not length:
                    raise ConnectionError()
            else:
                raise ConnectionError()
            await reader.readexactly(length + 2)
            return reader, writer
        except BaseException:
            await self._close_writer(writer)
            raise

    async def _handle(self, reader, writer):
        upstream_writer = None
        established = False
        try:
            # One total budget includes client negotiation, connect and proxy
            # negotiation, not a fresh timeout per received byte.
            async with asyncio.timeout(self.config.handshake_timeout):
                if not await self._request(reader, writer):
                    return
                upstream_reader, upstream_writer = await self._open_upstream()
                # Once success can be on the wire, never append a SOCKS error
                # to the opaque stream, even if its drain subsequently fails.
                established = True
                await self._write(writer, SUCCESS)
            await self._relay(reader, writer, upstream_reader, upstream_writer)
        except (OSError, EOFError, TimeoutError, ValueError):
            if not established:
                try:
                    await self._write(writer, FAILED)
                except (OSError, TimeoutError):
                    pass
        finally:
            await self._close_writer(upstream_writer)
            await self._close_writer(writer)

    async def _relay(self, client_reader, client_writer, upstream_reader, upstream_writer):
        loop = asyncio.get_running_loop()
        last_activity = loop.time()

        async def pump(reader, writer):
            nonlocal last_activity
            while data := await reader.read(BUFFER):
                last_activity = loop.time()
                await self._write(writer, data)
            # Don't cancel the reverse direction on EOF. HTTP/TLS peers can
            # still send buffered replies after a TCP write-half is closed.
            writer.write_eof()
            await asyncio.wait_for(writer.drain(), self.config.write_timeout)

        async def idle_watch():
            while True:
                remaining = self.config.idle_timeout - (loop.time() - last_activity)
                if remaining <= 0:
                    raise TimeoutError()
                await asyncio.sleep(remaining)

        pumps = [asyncio.create_task(pump(client_reader, upstream_writer)),
                 asyncio.create_task(pump(upstream_reader, client_writer))]
        transfer = asyncio.gather(*pumps)
        idle = asyncio.create_task(idle_watch())
        try:
            done, _ = await asyncio.wait((transfer, idle), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                await task
        finally:
            for task in [*pumps, idle, transfer]:
                task.cancel()
            await asyncio.gather(*pumps, idle, transfer, return_exceptions=True)


async def run(config):
    bridge = Bridge(config)
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stopped.set)
    try:
        await bridge.start()
        await stopped.wait()
    finally:
        await bridge.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind-ip", required=True)
    parser.add_argument("--allowed-host", required=True)
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--upstream-host")
    parser.add_argument("--upstream-port", type=int)
    parser.add_argument("--max-sessions", type=int, default=16)
    parser.add_argument("--handshake-timeout", type=float, default=10)
    parser.add_argument("--idle-timeout", type=float, default=120)
    parser.add_argument("--write-timeout", type=float, default=10)
    parser.add_argument("--close-timeout", type=float, default=1)
    try:
        config = Config(**vars(parser.parse_args()))
        # Port zero is available to local test callers, never the fixed CLI.
        if config.port == 0:
            raise ValueError()
    except (ValueError, TypeError):
        parser.error("invalid configuration")
    try:
        asyncio.run(run(config))
    except (OSError, ValueError):
        # No exception strings, endpoint addresses, or payloads in logs.
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
