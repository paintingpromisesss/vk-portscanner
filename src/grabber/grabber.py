import asyncio
import logging
from typing import List
from src.models.schemas import PortInfo


logger = logging.getLogger(__name__)

class BannerGrabber:
    def __init__(self, concurrency_limit: int = 100, timeout: int = 3):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency_limit)

    async def _grab(self, target: PortInfo) -> PortInfo:
        async with self.semaphore:
            reader = None
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.ip, target.port),
                    timeout=self.timeout
                )

                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                except asyncio.TimeoutError:
                    data = b""


                if not data:
                    probe = f"GET / HTTP/1.1\r\nHost: {target.ip}\r\n\r\n".encode('utf-8')
                    writer.write(probe)
                    await writer.drain()
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
                    except asyncio.TimeoutError:
                        data = b""

                if data:
                    banner_text = data.decode('utf-8', errors='replace').strip().split('\n')[0]
                    target.banner = banner_text[:200]
                    target.service = self._guess_service(target.port, banner_text)
                    logger.debug(f"[+] Grabber: {target.ip}:{target.port} -> {target.service} ({target.banner})")
                else:
                    target.service = self._guess_service(target.port, "")
                    logger.debug(f"[-] Grabber: {target.ip}:{target.port} return nothing. Prediction: {target.service}")
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                target.service = self._guess_service(target.port, "")
                logger.debug(f"[!] Grabber failed to connect to {target.ip}:{target.port}")

            finally:
                if writer:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
        return target

    def _guess_service(self, port: int, banner: str) -> str:
        banner_lower = banner.lower()

        if "ssh" in banner_lower:
            return "ssh"
        if "http" in banner_lower or "html" in banner_lower:
            return "http"
        if "ftp" in banner_lower:
            return "ftp"
        if "smtp" in banner_lower:
            return "smtp"

        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            443: "https",
            3306: "mysql",
            5432: "postgres",
            6379: "redis",
            8000: "http-alt",
            8080:"http-proxy",
        }

        return common_ports.get(int(port), "unknown")

    async def process_targets(self, targets: List[PortInfo]) -> List[PortInfo]:
        logger.info(f"Grabber: processing {len(targets)} targets")

        tasks = [self._grab(target) for target in targets]
        results = await asyncio.gather(*tasks)
        logger.info(f"Grabber: processed {len(results)} targets")
        return results
