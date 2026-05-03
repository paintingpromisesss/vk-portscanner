import asyncio
import logging
import re
import xml.etree.ElementTree as ET
from typing import List

from src.models.schemas import PortInfo

logger = logging.getLogger(__name__)


class VulnChecker:
    def __init__(self, concurrency_limit: int = 10, timeout: int = 60):
        self.semaphore = asyncio.Semaphore(concurrency_limit)
        self.timeout = timeout
        self.cve_pattern = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)

    async def _check_target(self, target: PortInfo) -> PortInfo:
        async with self.semaphore:
            logger.debug("Nmap is checking target %s:%s...", target.ip, target.port)

            cmd = [
                "nmap",
                "-sV",
                "--version-all",
                "-Pn",
                "-T4",
                "-p",
                str(target.port),
                "--script",
                "vulners",
                "-oX",
                "-",
                target.ip,
            ]

            process = None
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)

                if process.returncode != 0:
                    logger.warning(
                        "Nmap returned code %s for %s:%s: %s",
                        process.returncode,
                        target.ip,
                        target.port,
                        stderr.decode("utf-8", errors="ignore").strip(),
                    )
                    return target

                xml_output = stdout.decode("utf-8", errors="ignore")
                self._enrich_target_from_nmap(target, xml_output)
                return target

            except asyncio.TimeoutError:
                logger.warning("Timeout while checking target %s:%s", target.ip, target.port)
                if process and process.returncode is None:
                    process.kill()
                    await process.wait()
                return target
            except Exception:
                logger.exception("Error while checking target %s:%s", target.ip, target.port)
                return target

    def _enrich_target_from_nmap(self, target: PortInfo, xml_output: str) -> None:
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            logger.warning("Failed to parse Nmap XML for %s:%s", target.ip, target.port)
            return

        port_node = root.find(f".//port[@portid='{target.port}']")
        if port_node is None:
            logger.debug("Port node not found in Nmap XML for %s:%s", target.ip, target.port)
            return

        service_node = port_node.find("service")
        if service_node is not None:
            enriched_service = self._build_service_label(service_node)
            enriched_banner = self._build_banner(service_node)

            if enriched_service:
                target.service = enriched_service
            if enriched_banner:
                target.banner = enriched_banner[:200]

        found_cves = self._extract_cves(port_node)
        if found_cves:
            target.cve_list = found_cves
            logger.info("Found %s CVEs for target %s:%s", len(found_cves), target.ip, target.port)
        else:
            logger.debug("No CVEs found for target %s:%s", target.ip, target.port)

    def _build_service_label(self, service_node: ET.Element) -> str:
        name = (service_node.get("name") or "").strip()
        tunnel = (service_node.get("tunnel") or "").strip()

        if tunnel and tunnel.lower() == "ssl" and name and not name.startswith("ssl/"):
            return f"ssl/{name}"

        return name or "unknown"

    def _build_banner(self, service_node: ET.Element) -> str:
        parts = [
            (service_node.get("product") or "").strip(),
            (service_node.get("version") or "").strip(),
            (service_node.get("extrainfo") or "").strip(),
        ]
        banner = " ".join(part for part in parts if part).strip()
        return banner

    def _extract_cves(self, port_node: ET.Element) -> List[str]:
        raw_chunks: List[str] = []

        for script_node in port_node.findall(".//script"):
            script_id = (script_node.get("id") or "").strip().lower()
            if script_id != "vulners":
                continue

            output = script_node.get("output")
            if output:
                raw_chunks.append(output)

            for elem in script_node.iter():
                key = (elem.get("key") or "").strip()
                if key:
                    raw_chunks.append(key)
                if elem.text and elem.text.strip():
                    raw_chunks.append(elem.text.strip())

        cves = {
            match.upper()
            for chunk in raw_chunks
            for match in self.cve_pattern.findall(chunk)
        }
        return sorted(cves)

    async def check_vulnerabilities(self, targets: List[PortInfo]) -> List[PortInfo]:
        if not targets:
            return targets

        logger.info("Checking vulnerabilities for %s targets", len(targets))
        tasks = [self._check_target(target) for target in targets]
        results = await asyncio.gather(*tasks)
        logger.info("Finished checking vulnerabilities for %s targets", len(results))
        return results
