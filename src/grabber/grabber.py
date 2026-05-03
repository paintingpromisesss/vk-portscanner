import asyncio
import logging
import ssl
from typing import Awaitable, Callable, List

from src.models.schemas import PortInfo

logger = logging.getLogger(__name__)

ProbeFn = Callable[[PortInfo], Awaitable[tuple[str, str] | None]]


class BannerGrabber:
    def __init__(self, concurrency_limit: int = 100, timeout: int = 3):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    async def _grab(self, target: PortInfo) -> PortInfo:
        async with self.semaphore:
            for probe in self._probe_plan(target.port):
                try:
                    result = await probe(target)
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
                    continue

                if result is None:
                    continue

                banner, service = result
                target.banner = banner[:200] if banner else None
                target.service = service or self._guess_service(target.port, banner)
                logger.debug("[+] Grabber: %s:%s -> %s (%s)", target.ip, target.port, target.service, target.banner)
                return target

            target.service = self._guess_service(target.port, target.banner or "")
            logger.debug("[-] Grabber fallback: %s:%s -> %s", target.ip, target.port, target.service)
            return target

    def _probe_plan(self, port: int) -> List[ProbeFn]:
        if port in {80, 8080, 8000, 8081, 8888, 3000, 5000}:
            return [self._probe_http_plain, self._probe_passive]
        if port in {443, 8443, 9443}:
            return [self._probe_http_tls, self._probe_http_plain, self._probe_passive]
        if port in {25, 587, 2525}:
            return [self._probe_smtp, self._probe_passive]
        if port in {110, 995}:
            return [self._probe_pop3, self._probe_passive]
        if port in {143, 993}:
            return [self._probe_imap, self._probe_passive]
        if port == 6379:
            return [self._probe_redis, self._probe_passive]
        return [self._probe_passive, self._probe_http_plain]

    async def _probe_passive(self, target: PortInfo) -> tuple[str, str] | None:
        reader, writer = await self._open_connection(target.ip, target.port)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.2)
            if not data:
                return None
            banner = self._normalize_banner(data)
            return banner, self._guess_service(target.port, banner)
        finally:
            await self._close_writer(writer)

    async def _probe_http_plain(self, target: PortInfo) -> tuple[str, str] | None:
        reader, writer = await self._open_connection(target.ip, target.port)
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target.ip}\r\n"
                f"User-Agent: VK-PortScanner\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(request)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            if not data:
                return None
            return self._parse_http_banner(data), "http"
        finally:
            await self._close_writer(writer)

    async def _probe_http_tls(self, target: PortInfo) -> tuple[str, str] | None:
        reader, writer = await self._open_connection(target.ip, target.port, use_ssl=True)
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target.ip}\r\n"
                f"User-Agent: VK-PortScanner\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("utf-8")
            writer.write(request)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            if not data:
                return None
            return self._parse_http_banner(data), "https"
        finally:
            await self._close_writer(writer)

    async def _probe_smtp(self, target: PortInfo) -> tuple[str, str] | None:
        reader, writer = await self._open_connection(target.ip, target.port)
        try:
            greeting = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            writer.write(b"EHLO vk-portscanner.local\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            payload = greeting + b"\n" + response
            banner = self._normalize_banner(payload)
            return banner, "smtp"
        finally:
            await self._close_writer(writer)

    async def _probe_pop3(self, target: PortInfo) -> tuple[str, str] | None:
        reader, writer = await self._open_connection(target.ip, target.port)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if not data:
                return None
            return self._normalize_banner(data), "pop3"
        finally:
            await self._close_writer(writer)

    async def _probe_imap(self, target: PortInfo) -> tuple[str, str] | None:
        reader, writer = await self._open_connection(target.ip, target.port)
        try:
            greeting = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            writer.write(b"a001 CAPABILITY\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            payload = greeting + b"\n" + response
            banner = self._normalize_banner(payload)
            return banner, "imap"
        finally:
            await self._close_writer(writer)

    async def _probe_redis(self, target: PortInfo) -> tuple[str, str] | None:
        reader, writer = await self._open_connection(target.ip, target.port)
        try:
            writer.write(b"*1\r\n$4\r\nPING\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if not data:
                return None
            return self._normalize_banner(data), "redis"
        finally:
            await self._close_writer(writer)

    async def _open_connection(self, host: str, port: int, use_ssl: bool = False):
        return await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=self.ssl_context if use_ssl else None,
                server_hostname=host if use_ssl else None,
            ),
            timeout=self.timeout,
        )

    async def _close_writer(self, writer) -> None:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    def _parse_http_banner(self, data: bytes) -> str:
        text = data.decode("utf-8", errors="replace")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return ""

        status_line = lines[0]
        server_line = next((line for line in lines[1:] if line.lower().startswith("server:")), "")
        location_line = next((line for line in lines[1:] if line.lower().startswith("location:")), "")
        parts = [status_line]
        if server_line:
            parts.append(server_line)
        if location_line:
            parts.append(location_line)
        return " | ".join(parts)

    def _normalize_banner(self, data: bytes) -> str:
        text = data.decode("utf-8", errors="replace").replace("\r", "")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return " | ".join(lines[:2])[:200]

    def _guess_service(self, port: int, banner: str) -> str:
        banner_lower = (banner or "").lower()

        keyword_map = {
            "openssh": "ssh",
            "ssh-": "ssh",
            "http/": "http",
            "server:": "http",
            "nginx": "http",
            "apache": "http",
            "smtp": "smtp",
            "ftp": "ftp",
            "redis": "redis",
            "+pong": "redis",
            "imap": "imap",
            "pop3": "pop3",
            "+ok": "pop3",
            "mysql": "mysql",
            "postgresql": "postgres",
            "cloudflare": "http",
        }

        for needle, service in keyword_map.items():
            if needle in banner_lower:
                return service

        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            587: "smtp",
            993: "imaps",
            995: "pop3s",
            3306: "mysql",
            5432: "postgres",
            6379: "redis",
            8000: "http-alt",
            8080: "http-proxy",
            8443: "https-alt",
        }

        return common_ports.get(int(port), "unknown")

    async def process_targets(self, targets: List[PortInfo]) -> List[PortInfo]:
        logger.info("Grabber: processing %s targets", len(targets))
        tasks = [self._grab(target) for target in targets]
        results = await asyncio.gather(*tasks)
        logger.info("Grabber: processed %s targets", len(results))
        return results
