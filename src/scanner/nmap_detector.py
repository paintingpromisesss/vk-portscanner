import asyncio
import logging
import re
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Iterable, List

from src.models.schemas import PortInfo

logger = logging.getLogger(__name__)


class NmapServiceDetector:
    def __init__(self, executable_path: str = "nmap", timeout: int = 30, enabled: bool = True):
        self.executable_path = executable_path
        self.timeout = timeout
        self.enabled = enabled

    async def enrich_ports(self, ports: List[PortInfo]) -> List[PortInfo]:
        if not self.enabled:
            logger.info("Nmap service detection is disabled")
            return ports
        if not ports:
            return ports

        detected = await self._detect(ports)
        if not detected:
            return ports

        for port in ports:
            enriched = detected.get((port.ip, port.port, port.protocol))
            if enriched is None:
                continue
            if self._should_replace(port, enriched):
                port.service = enriched.service or port.service
                port.banner = enriched.banner or port.banner

        return ports

    async def _detect(self, ports: Iterable[PortInfo]) -> dict[tuple[str, int, str], PortInfo]:
        grouped_ports: dict[str, set[int]] = defaultdict(set)
        for port in ports:
            if (port.protocol or "tcp") == "tcp":
                grouped_ports[port.ip].add(port.port)

        results: dict[tuple[str, int, str], PortInfo] = {}
        for ip, ip_ports in grouped_ports.items():
            detected_ports = await self._scan_host(ip, sorted(ip_ports))
            for detected_port in detected_ports:
                results[(detected_port.ip, detected_port.port, detected_port.protocol)] = detected_port
        return results

    async def _scan_host(self, ip: str, ports: list[int]) -> list[PortInfo]:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as temp_file:
            output_path = Path(temp_file.name)

        cmd = [
            self.executable_path,
            "-sV",
            "--version-light",
            "-Pn",
            "-p",
            ",".join(str(port) for port in ports),
            "-oX",
            str(output_path),
            ip,
        ]
        logger.info("running nmap service detection: %s", " ".join(cmd))

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        except FileNotFoundError:
            logger.warning("nmap executable not found. Skipping service detection.")
            output_path.unlink(missing_ok=True)
            return []
        except asyncio.TimeoutError:
            logger.warning("nmap service detection timed out for %s", ip)
            if process is not None:
                process.kill()
                await process.wait()
            output_path.unlink(missing_ok=True)
            return []

        if not output_path.exists():
            return []

        if process.returncode != 0:
            logger.warning("nmap service detection failed for %s: %s", ip, stderr.decode(errors="replace"))
            output_path.unlink(missing_ok=True)
            return []

        try:
            return self._parse_xml(output_path)
        finally:
            output_path.unlink(missing_ok=True)

    def _parse_xml(self, output_path: Path) -> list[PortInfo]:
        try:
            root = ET.parse(output_path).getroot()
        except ET.ParseError as exc:
            logger.warning("failed to parse nmap XML output: %s", exc)
            return []

        results: list[PortInfo] = []
        for host in root.findall("host"):
            address = host.find("address")
            if address is None:
                continue
            ip = address.attrib.get("addr")
            if not ip:
                continue

            for port_node in host.findall("./ports/port"):
                state = port_node.find("state")
                if state is not None and state.attrib.get("state") != "open":
                    continue

                port = int(port_node.attrib["portid"])
                protocol = port_node.attrib.get("protocol", "tcp")
                service_node = port_node.find("service")
                service, banner = self._service_from_node(service_node)
                results.append(PortInfo(ip=ip, port=port, protocol=protocol, service=service, banner=banner))

        logger.info("nmap service detection parsed %s service result(s)", len(results))
        return results

    def _service_from_node(self, service_node: ET.Element | None) -> tuple[str | None, str | None]:
        if service_node is None:
            return None, None

        name = service_node.attrib.get("name")
        product = service_node.attrib.get("product")
        version = service_node.attrib.get("version")
        extrainfo = service_node.attrib.get("extrainfo")

        banner_parts = [part for part in (product, version, extrainfo) if part]
        banner = " ".join(banner_parts) if banner_parts else None
        return name, banner

    def _should_replace(self, current: PortInfo, detected: PortInfo) -> bool:
        current_banner = current.normalized_banner()
        detected_banner = detected.normalized_banner()
        if not detected_banner:
            return False
        if not current_banner:
            return True
        return self._has_version(detected_banner) and not self._has_version(current_banner)

    def _has_version(self, value: str) -> bool:
        product_version_patterns = [
            r"apache(?: httpd)?[/\s]+\d+(?:\.\d+)+",
            r"openssh[_\s-]+\d+(?:\.\d+)+",
            r"nginx[/\s]+\d+(?:\.\d+)+",
            r"redis(?: server)?[/\s]+\d+(?:\.\d+)+",
            r"postfix[/\s]+\d+(?:\.\d+)+",
            r"mysql[/\s]+\d+(?:\.\d+)+",
            r"postgresql[/\s]+\d+(?:\.\d+)+",
        ]
        lower_value = value.lower()
        return any(re.search(pattern, lower_value) for pattern in product_version_patterns)
