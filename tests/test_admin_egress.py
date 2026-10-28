"""Public SOCKS sockets only; fixtures require loopback, never DNS/Internet."""
import asyncio
from pathlib import Path
import socket
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import admin_egress


HOST = b"admin.example.invalid"
REQUEST = b"\x05\x01\x00\x03" + bytes([len(HOST)]) + HOST + b"\x01\xbb"
SUCCESS = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
DENIED = b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00"
FAILED = b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00"


class AdminEgressTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.writers = []
        self.fixture_tasks = set()
        self.contacts = asyncio.Queue()
        self.disconnections = asyncio.Queue()
        self.fixture_errors = []
        self.proxy_greeting = b"\x05\x00"
        self.proxy_reply = SUCCESS
        self.proxy_stall = False
        self.proxy_sink_stall = False
        self.proxy_push = False

        async def upstream(reader, writer):
            task = asyncio.current_task()
            self.fixture_tasks.add(task)
            try:
                await self.contacts.put(True)
                self.assertEqual(await reader.readexactly(3), b"\x05\x01\x00")
                if self.proxy_stall:
                    self.assertEqual(await reader.read(), b"")
                    return
                writer.write(self.proxy_greeting)
                await writer.drain()
                if self.proxy_greeting != b"\x05\x00":
                    self.assertEqual(await reader.read(), b"")
                    return
                self.assertEqual(await reader.readexactly(len(REQUEST)), REQUEST)
                writer.write(self.proxy_reply)
                await writer.drain()
                if self.proxy_reply[:4] not in (SUCCESS[:4], b"\x05\x00\x00\x03", b"\x05\x00\x00\x04"):
                    self.assertEqual(await reader.read(), b"")
                    return
                if self.proxy_push:
                    for _ in range(10):
                        await asyncio.sleep(0.03)
                        writer.write(b"tick")
                        await writer.drain()
                if self.proxy_sink_stall:
                    await asyncio.Future()
                while chunk := await reader.read(65536):
                    writer.write(chunk)
                    await writer.drain()
                # Reply after EOF proves the relay preserves TCP half-close.
                writer.write(b"after-eof")
                await writer.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass  # Expected when exercising abort/cancel paths.
            except Exception as error:
                self.fixture_errors.append(error)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass
                self.fixture_tasks.discard(task)
                self.disconnections.put_nowait(True)

        self.upstream = await asyncio.start_server(upstream, "127.0.0.1", 0)
        self.addAsyncCleanup(self.cleanup)
        self.bridge = None

    async def cleanup(self):
        for writer in self.writers:
            writer.close()
        for writer in self.writers:
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        if self.bridge:
            await self.bridge.close()
        self.upstream.close()
        tasks = list(self.fixture_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.upstream.wait_closed()
        self.assertEqual(self.fixture_errors, [])

    async def start_bridge(self, **overrides):
        options = dict(bind_ip="127.0.0.1", port=0, allowed_host=HOST.decode(),
                       upstream_host="127.0.0.1",
                       upstream_port=self.upstream.sockets[0].getsockname()[1],
                       handshake_timeout=0.5, idle_timeout=1, write_timeout=0.5,
                       close_timeout=0.2, max_sessions=8)
        options.update(overrides)
        self.bridge = admin_egress.Bridge(admin_egress.Config(**options))
        await self.bridge.start()

    async def connect(self, negotiate=True):
        reader, writer = await asyncio.open_connection(*self.bridge.address)
        self.writers.append(writer)
        if negotiate:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(2), 2), b"\x05\x00")
        return reader, writer

    async def test_exact_domain_443_forwards_and_preserves_half_close(self):
        await self.start_bridge()
        reader, writer = await self.connect()
        writer.write(REQUEST)
        await writer.drain()
        self.assertEqual(await reader.readexactly(10), SUCCESS)
        writer.write(b"opaque TLS bytes\x00\xff")
        await writer.drain()
        self.assertEqual(await reader.readexactly(18), b"opaque TLS bytes\x00\xff")
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"after-eof")
        self.assertEqual(self.contacts.qsize(), 1)

    async def test_denies_other_hosts_ports_ip_atyps_and_commands_before_upstream(self):
        await self.start_bridge()
        denied = [
            REQUEST[:-2] + b"\x00\x50",  # HTTP
            REQUEST[:-2] + b"\x01\xbc",  # 444
            b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb",
            b"\x05\x01\x00\x04" + b"\x00" * 15 + b"\x01\x01\xbb",
            b"\x05\x02" + REQUEST[2:],  # BIND
            b"\x05\x03" + REQUEST[2:],  # UDP
            b"\x04" + REQUEST[1:],
            REQUEST[:2] + b"\x01" + REQUEST[3:],  # reserved byte
            REQUEST[:3] + b"\x05",  # unknown ATYP
            REQUEST[:4] + b"\x00",  # empty domain
        ]
        for host in (b"other.example.invalid", b"127.0.0.1", b"::1", HOST.upper(), HOST + b".",
                     b"*", b"admin.example.invalid.evil", b"\xff" * len(HOST),
                     b"\x00" + HOST[1:]):
            denied.append(REQUEST[:4] + bytes([len(host)]) + host + b"\x01\xbb")
        for request in denied:
            with self.subTest(request=request):
                reader, writer = await self.connect()
                writer.write(request)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), DENIED)
        self.assertTrue(self.contacts.empty())

    async def test_truncated_domain_request_fails_closed_before_upstream(self):
        await self.start_bridge()
        reader, writer = await self.connect()
        writer.write(REQUEST[:-1])
        await writer.drain()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), FAILED)
        self.assertTrue(self.contacts.empty())

    async def test_rejects_invalid_greeting_and_auth_without_upstream(self):
        await self.start_bridge()
        for greeting, reply in ((b"\x05\x01\x02", b"\x05\xff"),
                                (b"\x05\x00", b""), (b"\x04\x01\x00", b"")):
            reader, writer = await self.connect(negotiate=False)
            writer.write(greeting)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), reply)
        self.assertTrue(self.contacts.empty())

    async def test_eight_live_sessions_and_excess_connections_rejected_then_slot_reused(self):
        await self.start_bridge()
        sessions = []
        for _ in range(8):
            reader, writer = await self.connect()
            writer.write(REQUEST)
            await writer.drain()
            self.assertEqual(await reader.readexactly(10), SUCCESS)
            sessions.append((reader, writer))
        extra, _ = await self.connect(negotiate=False)
        self.assertEqual(await asyncio.wait_for(extra.read(), 2), b"")
        self.assertEqual(self.contacts.qsize(), 8)
        first, writer = sessions.pop()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(first.read(), 2), b"after-eof")
        # EOF reaches the client just before the bridge completes its cleanup.
        async def replacement():
            while True:
                reader, writer = await self.connect(negotiate=False)
                writer.write(b"\x05\x01\x00")
                try:
                    if await reader.readexactly(2) == b"\x05\x00":
                        return reader, writer
                except (ConnectionError, asyncio.IncompleteReadError):
                    await asyncio.sleep(0.01)
        reader, writer = await asyncio.wait_for(replacement(), 2)
        writer.write(REQUEST)
        await writer.drain()
        self.assertEqual(await reader.readexactly(10), SUCCESS)
        self.assertEqual(self.contacts.qsize(), 9)

    async def test_handshake_deadline_closes_slow_client_before_upstream(self):
        await self.start_bridge(handshake_timeout=0.08)
        reader, writer = await self.connect(negotiate=False)
        writer.write(b"\x05\x01")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), FAILED)
        self.assertTrue(self.contacts.empty())

    async def test_upstream_stall_is_bounded_and_connection_is_cleaned_up(self):
        self.proxy_stall = True
        await self.start_bridge(handshake_timeout=0.08)
        reader, writer = await self.connect()
        writer.write(REQUEST)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), FAILED)
        await asyncio.wait_for(self.disconnections.get(), 1)

    async def test_idle_session_closes_both_sockets_without_error_bytes(self):
        await self.start_bridge(idle_timeout=0.08)
        reader, writer = await self.connect()
        writer.write(REQUEST)
        await writer.drain()
        self.assertEqual(await reader.readexactly(10), SUCCESS)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        await asyncio.wait_for(self.disconnections.get(), 1)

    async def test_one_way_activity_keeps_session_alive_past_idle_budget(self):
        self.proxy_push = True
        await self.start_bridge(idle_timeout=0.12)
        reader, writer = await self.connect()
        writer.write(REQUEST)
        await writer.drain()
        self.assertEqual(await reader.readexactly(10), SUCCESS)
        self.assertEqual(await asyncio.wait_for(reader.readexactly(40), 2), b"tick" * 10)
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"after-eof")

    async def test_blocked_upstream_write_is_bounded_before_idle_deadline(self):
        self.proxy_sink_stall = True
        await self.start_bridge(write_timeout=0.08, idle_timeout=5)
        reader, writer = await self.connect()
        writer.write(REQUEST)
        await writer.drain()
        self.assertEqual(await reader.readexactly(10), SUCCESS)

        async def flood():
            try:
                for _ in range(1024):
                    writer.write(b"x" * 65536)
                    await writer.drain()
            except ConnectionError:
                pass

        sender = asyncio.create_task(flood())
        try:
            try:
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            except ConnectionError:
                pass  # An abort with unread input can appear as TCP RST.
        finally:
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)

    async def test_fixed_cli_forwards_without_logging_and_sigterm_cleans_up(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        script = Path(__file__).resolve().parents[1] / "scripts" / "admin_egress.py"
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-I", "-B", str(script), "--bind-ip", "127.0.0.1",
            "--port", str(port), "--allowed-host", HOST.decode(),
            "--upstream-host", "127.0.0.1", "--upstream-port",
            str(self.upstream.sockets[0].getsockname()[1]),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            async def ready():
                while True:
                    if process.returncode is not None:
                        self.fail("bridge exited before listening")
                    try:
                        return await asyncio.open_connection("127.0.0.1", port)
                    except ConnectionRefusedError:
                        await asyncio.sleep(0.02)
            reader, writer = await asyncio.wait_for(ready(), 3)
            self.writers.append(writer)
            writer.write(b"\x05\x01\x00" + REQUEST)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(12), 2), b"\x05\x00" + SUCCESS)
            writer.write(b"do-not-log-this-opaque-content")
            await writer.drain()
            self.assertEqual(await reader.readexactly(30), b"do-not-log-this-opaque-content")
            process.terminate()
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            output, error = await asyncio.wait_for(process.communicate(), 2)
            self.assertEqual((process.returncode, output, error), (0, b"", b""))
        finally:
            if process.returncode is None:
                process.kill()
                await process.communicate()

    async def test_shutdown_cancels_active_and_handshaking_sessions_and_closes_listener(self):
        await self.start_bridge()
        reader, writer = await self.connect()
        writer.write(REQUEST)
        await writer.drain()
        self.assertEqual(await reader.readexactly(10), SUCCESS)
        pending, _ = await self.connect(negotiate=False)
        address = self.bridge.address
        await asyncio.wait_for(self.bridge.close(), 1)
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertEqual(await asyncio.wait_for(pending.read(), 1), b"")
        await asyncio.wait_for(self.disconnections.get(), 1)
        with self.assertRaises(OSError):
            await asyncio.open_connection(*address)

    async def test_upstream_rejects_auth_and_failure_without_fallback(self):
        for greeting, reply in ((b"\x05\x02", SUCCESS),
                                (b"\x04\x00", SUCCESS),
                                (b"\x05\x00", b"\x05\x05\x00\x01" + b"\x00" * 6),
                                (b"\x05\x00", b"\x05\x00\x01\x01" + b"\x00" * 6),
                                (b"\x05\x00", b"\x05\x00\x00\x09"),
                                (b"\x05\x00", b"\x05\x00\x00\x03\x00"),
                                (b"\x05\x00", b"\x05\x00\x00\x03\x03x")):
            with self.subTest(greeting=greeting, reply=reply):
                self.proxy_greeting, self.proxy_reply = greeting, reply
                await self.start_bridge()
                reader, writer = await self.connect()
                writer.write(REQUEST)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), FAILED)
                await asyncio.wait_for(self.disconnections.get(), 1)
                await self.bridge.close()
        self.assertEqual(self.contacts.qsize(), 7)

    async def test_valid_upstream_domain_and_ipv6_bound_replies_are_accepted(self):
        for reply in (b"\x05\x00\x00\x03\x01x\x00\x00",
                      b"\x05\x00\x00\x04" + b"\x00" * 18):
            with self.subTest(reply=reply):
                self.proxy_reply = reply
                await self.start_bridge()
                reader, writer = await self.connect()
                writer.write(REQUEST)
                await writer.drain()
                self.assertEqual(await reader.readexactly(10), SUCCESS)
                writer.write_eof()
                self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"after-eof")
                await self.bridge.close()


class ConfigurationTests(unittest.TestCase):
    def test_unsafe_configuration_fails_before_listening(self):
        bad = [dict(bind_ip="0.0.0.0"), dict(bind_ip="::"), dict(bind_ip="224.0.0.1"),
               dict(allowed_host="127.0.0.1"), dict(allowed_host="::1"),
               dict(allowed_host="127.1"), dict(allowed_host="0x7f.0.0.1"),
               dict(allowed_host="127.0x0.0x0.0x1"),
               dict(allowed_host="ADMIN.example.invalid"), dict(allowed_host="a.invalid."),
               dict(allowed_host="https://admin.example.invalid"),
               dict(allowed_host="x..invalid"), dict(allowed_host="*.invalid"),
               dict(allowed_host="a" * 64 + ".invalid"),
               dict(upstream_host="127.0.0.1"), dict(upstream_port=1080),
               dict(upstream_host="user:password@proxy.invalid", upstream_port=1080),
               dict(upstream_host="socks5://proxy.invalid", upstream_port=1080),
               dict(max_sessions=7), dict(max_sessions=257), dict(port=-1)]
        for field in ("handshake_timeout", "idle_timeout", "write_timeout", "close_timeout"):
            for value in (0, -1, float("nan"), float("inf"), 3601):
                bad.append({field: value})
        for options in bad:
            with self.subTest(options=options), self.assertRaises(ValueError):
                admin_egress.Config(**(dict(bind_ip="127.0.0.1", allowed_host=HOST.decode()) | options))


if __name__ == "__main__":
    unittest.main()
