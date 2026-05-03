from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

class PortInfo(BaseModel):
    ip: str
    port: int
    protocol: str = "tcp"

    service: Optional[str] = None
    banner: Optional[str] = None
    cve_list: List[str] = Field(default_factory=list)

    discovered_at: datetime = Field(default_factory=datetime.now)

    def normalized_service(self) -> str:
        return (self.service or "unknown").strip()

    def normalized_banner(self) -> str:
        return (self.banner or "").strip()

    def normalized_cve_list(self) -> List[str]:
        return sorted({cve.strip() for cve in self.cve_list if cve.strip()})

    def state_dict(self) -> dict:
        return {
            "service": self.normalized_service(),
            "banner": self.normalized_banner(),
            "cve_list": self.normalized_cve_list(),
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
        return "updated"

class ScanResult(BaseModel):
    scan_id: str
    targets: str
    total_found: int
    ports: List[PortInfo] = Field(default_factory=list)
    finished_at: datetime = Field(default_factory=datetime.now)
