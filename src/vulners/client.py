import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable, List

from src.models.schemas import PortInfo, VulnerabilityInfo, VulnerabilitySummary

logger = logging.getLogger(__name__)

VULNERS_FIELDS = [
    "title",
    "short_description",
    "href",
    "cvelist",
    "ai_score",
    "metrics",
    "exploitation",
]


@dataclass(frozen=True)
class SoftwareInfo:
    product: str
    version: str
    vendor: str | None = None

    def as_vulners_payload(self) -> dict[str, str]:
        payload = {"product": self.product, "version": self.version}
        if self.vendor:
            payload["vendor"] = self.vendor
        return payload


class VulnersClient:
    def __init__(
        self,
        api_key: str,
        enabled: bool = False,
        max_results_per_service: int = 5,
        api: Any | None = None,
    ):
        self.api_key = api_key
        self.enabled = enabled
        self.max_results_per_service = max_results_per_service
        self.api = api

    async def enrich_ports(self, ports: List[PortInfo]) -> List[PortInfo]:
        if not self.enabled:
            logger.info("Vulners enrichment is disabled")
            return ports
        if not self.api_key and self.api is None:
            logger.warning("Vulners enrichment is enabled, but api_key is empty")
            return ports

        enriched_ports = []
        for port in ports:
            enriched_ports.append(await self.enrich_port(port))
        return enriched_ports

    async def enrich_port(self, port: PortInfo) -> PortInfo:
        software = self.extract_software(port)
        if software is None:
            logger.info(
                "Vulners: skipped %s:%s, no product/version extracted from service=%s banner=%s",
                port.ip,
                port.port,
                port.normalized_service(),
                port.normalized_banner() or "empty banner",
            )
            return port

        try:
            if self.api is not None:
                result = self._audit_software(software)
            else:
                result = await asyncio.to_thread(self._audit_software, software)
        except Exception as exc:
            logger.warning(
                "Vulners lookup failed for %s:%s %s %s: %s",
                port.ip,
                port.port,
                software.product,
                software.version,
                exc,
            )
            return port

        summary = self._build_summary(result)
        if summary.total_count > 0:
            port.vulnerabilities = summary
            logger.info(
                "Vulners: %s:%s %s %s -> %s vulnerabilities, max severity %s",
                port.ip,
                port.port,
                software.product,
                software.version,
                summary.total_count,
                summary.severity,
            )
        else:
            logger.info(
                "Vulners: %s:%s %s %s -> 0 vulnerabilities",
                port.ip,
                port.port,
                software.product,
                software.version,
            )
        return port

    def extract_software(self, port: PortInfo) -> SoftwareInfo | None:
        banner = port.normalized_banner()
        service = port.normalized_service().lower()
        text = f"{service} {banner}".lower()

        patterns = [
            (r"nginx[/\s]+(?P<version>\d+(?:\.\d+){1,3})", "nginx", "nginx"),
            (r"apache(?: httpd)?[/\s]+(?P<version>\d+(?:\.\d+){1,3})", "apache httpd", "apache"),
            (r"openssh[_\s-]+(?P<version>\d+(?:\.\d+){1,3})", "openssh", "openbsd"),
            (r"redis(?: server)?[/\s]+(?P<version>\d+(?:\.\d+){1,3})", "redis", "redis"),
            (r"postfix[/\s]+(?P<version>\d+(?:\.\d+){1,3})", "postfix", "postfix"),
            (r"mysql[/\s]+(?P<version>\d+(?:\.\d+){1,3})", "mysql", "oracle"),
            (r"postgresql[/\s]+(?P<version>\d+(?:\.\d+){1,3})", "postgresql", "postgresql"),
        ]

        for pattern, product, vendor in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                return SoftwareInfo(product=product, version=match.group("version"), vendor=vendor)

        return None

    def _audit_software(self, software: SoftwareInfo) -> Any:
        api = self._api()
        return api.audit.software(
            software=[software.as_vulners_payload()],
            fields=VULNERS_FIELDS,
            match="partial",
            catalog="extended",
        )

    def _api(self) -> Any:
        if self.api is not None:
            return self.api

        import vulners

        self.api = vulners.VulnersApi(api_key=self.api_key)
        return self.api

    def _build_summary(self, audit_result: Any) -> VulnerabilitySummary:
        vulnerabilities = self._extract_vulnerabilities(audit_result)
        infos = [self._to_vulnerability_info(item) for item in vulnerabilities]
        infos.sort(key=lambda item: item.score or 0, reverse=True)

        top = infos[: self.max_results_per_service]
        max_score = top[0].score if top else None
        return VulnerabilitySummary(
            total_count=len(infos),
            max_score=max_score,
            severity=self._severity(max_score),
            top=top,
        )

    def _extract_vulnerabilities(self, audit_result: Any) -> list[dict[str, Any]]:
        if isinstance(audit_result, dict):
            raw_items: Iterable[Any] = [audit_result]
        elif isinstance(audit_result, list):
            raw_items = audit_result
        else:
            return []

        vulnerabilities: list[dict[str, Any]] = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            for vulnerability in item.get("vulnerabilities", []):
                if isinstance(vulnerability, dict):
                    vulnerabilities.append(vulnerability)
        return vulnerabilities

    def _to_vulnerability_info(self, item: dict[str, Any]) -> VulnerabilityInfo:
        cves = item.get("cvelist") or []
        if isinstance(cves, str):
            cves = [cves]

        return VulnerabilityInfo(
            id=str(item.get("id") or item.get("title") or "unknown"),
            cves=[str(cve) for cve in cves],
            title=item.get("title"),
            score=self._score(item),
            href=item.get("href"),
            description=item.get("short_description"),
        )

    def _score(self, item: dict[str, Any]) -> float | None:
        ai_score = item.get("ai_score")
        if isinstance(ai_score, dict):
            value = ai_score.get("value")
            if isinstance(value, (int, float)):
                return float(value)

        metrics = item.get("metrics")
        if isinstance(metrics, dict):
            for metric_name in ("cvss3", "cvss"):
                metric = metrics.get(metric_name)
                if isinstance(metric, dict):
                    value = metric.get("score") or metric.get("baseScore")
                    if isinstance(value, (int, float)):
                        return float(value)

        return None

    def _severity(self, score: float | None) -> str:
        if score is None:
            return "UNKNOWN"
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"
