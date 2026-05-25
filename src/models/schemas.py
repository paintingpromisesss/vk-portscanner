from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class VulnerabilityInfo(BaseModel):
    id: str
    cves: List[str] = Field(default_factory=list)
    title: Optional[str] = None
    score: Optional[float] = None
    href: Optional[str] = None
    description: Optional[str] = None


class VulnerabilitySummary(BaseModel):
    total_count: int = 0
    max_score: Optional[float] = None
    severity: str = "NONE"
    top: List[VulnerabilityInfo] = Field(default_factory=list)

    def normalized_dict(self) -> dict:
        return {
            "total_count": self.total_count,
            "max_score": self.max_score,
            "severity": self.severity,
            "top": [item.model_dump() for item in self.top],
        }


class PortInfo(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"

    service: Optional[str] = None
    banner: Optional[str] = None
    vulnerabilities: Optional[VulnerabilitySummary] = None

    discovered_at: datetime = Field(default_factory=datetime.now)

    def normalized_service(self) -> str:
        return (self.service or "unknown").strip()

    def normalized_banner(self) -> str:
        return (self.banner or "").strip()

    def state_dict(self) -> dict:
        vulnerabilities = self.vulnerabilities.normalized_dict() if self.vulnerabilities else None
        return {
            "service": self.normalized_service(),
            "banner": self.normalized_banner(),
            "vulnerabilities": vulnerabilities,
        }

    def state_equals(self, other: "PortInfo") -> bool:
        return (
            self.ip == other.ip
            and self.port == other.port
            and self.protocol == other.protocol
            and self.state_dict() == other.state_dict()
        )


class PortChange(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"
    before: Optional[PortInfo] = None
    after: Optional[PortInfo] = None
    changed_at: datetime = Field(default_factory=datetime.now)

    @property
    def change_type(self) -> str:
        if self.before is None and self.after is not None:
            return "new"
        if self.before is not None and self.after is None:
            return "closed"
        if (
            self.before is not None
            and self.after is not None
            and self.after.vulnerabilities is not None
            and self.after.vulnerabilities.total_count > 0
            and self._vulnerability_state(self.before) != self._vulnerability_state(self.after)
        ):
            return "risk"
        if (
            self.before is not None
            and self.after is not None
            and self.before.state_equals(self.after)
            and self.after.vulnerabilities is not None
            and self.after.vulnerabilities.total_count > 0
        ):
            return "risk"
        return "updated"

    def _vulnerability_state(self, port: Optional[PortInfo]) -> dict | None:
        if port is None or port.vulnerabilities is None:
            return None
        return port.vulnerabilities.normalized_dict()

class ScanResult(BaseModel):
    scan_id: str
    targets: str
    total_found: int
    ports: List[PortInfo] = Field(default_factory=list)
    finished_at: datetime = Field(default_factory=datetime.now)
