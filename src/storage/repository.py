import json
import logging
import sqlite3
from datetime import datetime
from typing import Dict, List, Tuple

from pydantic import ValidationError

from src.models.schemas import PortChange, PortInfo, VulnerabilitySummary
from src.storage.database import DB_PATH

logger = logging.getLogger(__name__)


class PortRepository:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    async def save_scan_diff(self, ports: List[PortInfo], scan_scope: str) -> List[PortChange]:
        changes: List[PortChange] = []
        observed_keys = {self._port_key(port) for port in ports}

        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            existing_rows = self._load_existing_ports(db)
            previous_scope = self._get_metadata(db, "last_scan_scope")

            for port in ports:
                before = existing_rows.get(self._port_key(port))
                if before is None:
                    self._insert_current_state(db, port, scan_scope)
                    changes.append(PortChange(after=port, ip=port.ip, port=port.port, protocol=port.protocol))
                    continue

                if before.state_equals(port) and before.protocol == port.protocol:
                    self._mark_seen_without_changes(db, port, scan_scope)
                    continue

                self._update_current_state(db, port, scan_scope)
                changes.append(
                    PortChange(
                        before=before,
                        after=port,
                        ip=port.ip,
                        port=port.port,
                        protocol=port.protocol,
                    )
                )

            if previous_scope == scan_scope:
                for key, existing_port in existing_rows.items():
                    if (
                        key in observed_keys
                        or not self._is_port_open(existing_port)
                        or self._get_scan_scope(existing_port) != scan_scope
                    ):
                        continue

                    self._mark_closed(db, existing_port)
                    changes.append(
                        PortChange(
                            before=existing_port,
                            after=None,
                            ip=existing_port.ip,
                            port=existing_port.port,
                            protocol=existing_port.protocol,
                        )
                    )
            elif previous_scope is not None:
                logger.info(
                    "Scan scope changed from %s to %s. Skipping close detection for this run.",
                    previous_scope,
                    scan_scope,
                )

            for change in changes:
                self._insert_change_log(db, change)

            self._set_metadata(db, "last_scan_scope", scan_scope)
            db.commit()

        if changes:
            logger.info("Detected %s changes after diff", len(changes))
        else:
            logger.info("No changes detected after diff")

        return changes

    def _load_existing_ports(self, db: sqlite3.Connection) -> Dict[Tuple[str, int, str], PortInfo]:
        rows = db.execute("""
            SELECT
                ip, port, protocol, service, banner,
                vulnerability_summary,
                discovered_at, is_open, scan_scope
            FROM ports
        """).fetchall()

        existing_ports: Dict[Tuple[str, int, str], PortInfo] = {}
        for row in rows:
            port = PortInfo(
                ip=row["ip"],
                port=row["port"],
                protocol=row["protocol"] or "tcp",
                service=row["service"],
                banner=row["banner"],
                vulnerabilities=self._parse_vulnerability_summary(row["vulnerability_summary"]),
                discovered_at=self._parse_datetime(row["discovered_at"]),
            )
            port.__dict__["is_open"] = bool(row["is_open"])
            port.__dict__["scan_scope"] = row["scan_scope"]
            existing_ports[self._port_key(port)] = port

        return existing_ports

    def _insert_current_state(self, db: sqlite3.Connection, port: PortInfo, scan_scope: str) -> None:
        timestamp = datetime.now()
        db.execute(
            """
            INSERT INTO ports (
                ip, port, protocol, service, banner,
                vulnerability_count, vulnerability_max_score,
                vulnerability_severity, vulnerability_summary,
                is_open, scan_scope, discovered_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """,
            (
                port.ip,
                port.port,
                port.protocol,
                port.normalized_service(),
                port.normalized_banner(),
                self._vulnerability_count(port),
                self._vulnerability_max_score(port),
                self._vulnerability_severity(port),
                self._vulnerability_summary_json(port),
                scan_scope,
                port.discovered_at.isoformat(),
                timestamp.isoformat(),
            ),
        )

    def _update_current_state(self, db: sqlite3.Connection, port: PortInfo, scan_scope: str) -> None:
        db.execute(
            """
            UPDATE ports
            SET
                service = ?,
                banner = ?,
                vulnerability_count = ?,
                vulnerability_max_score = ?,
                vulnerability_severity = ?,
                vulnerability_summary = ?,
                is_open = 1,
                scan_scope = ?,
                updated_at = ?
            WHERE ip = ? AND port = ? AND protocol = ?
            """,
            (
                port.normalized_service(),
                port.normalized_banner(),
                self._vulnerability_count(port),
                self._vulnerability_max_score(port),
                self._vulnerability_severity(port),
                self._vulnerability_summary_json(port),
                scan_scope,
                datetime.now().isoformat(),
                port.ip,
                port.port,
                port.protocol,
            ),
        )

    def _mark_seen_without_changes(self, db: sqlite3.Connection, port: PortInfo, scan_scope: str) -> None:
        db.execute(
            """
            UPDATE ports
            SET is_open = 1, scan_scope = ?, updated_at = ?
            WHERE ip = ? AND port = ? AND protocol = ?
            """,
            (scan_scope, datetime.now().isoformat(), port.ip, port.port, port.protocol),
        )

    def _mark_closed(self, db: sqlite3.Connection, port: PortInfo) -> None:
        db.execute(
            """
            UPDATE ports
            SET is_open = 0, updated_at = ?
            WHERE ip = ? AND port = ? AND protocol = ?
            """,
            (datetime.now().isoformat(), port.ip, port.port, port.protocol),
        )

    def _insert_change_log(self, db: sqlite3.Connection, change: PortChange) -> None:
        db.execute(
            """
            INSERT INTO port_changes (
                ip, port, protocol, change_type,
                before_service, before_banner,
                after_service, after_banner,
                after_vulnerability_count,
                after_vulnerability_max_score,
                after_vulnerability_severity,
                after_vulnerability_summary,
                changed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                change.ip,
                change.port,
                change.protocol,
                change.change_type,
                self._service(change.before),
                self._banner(change.before),
                self._service(change.after),
                self._banner(change.after),
                self._vulnerability_count(change.after),
                self._vulnerability_max_score(change.after),
                self._vulnerability_severity(change.after),
                self._vulnerability_summary_json(change.after),
                change.changed_at.isoformat(),
            ),
        )

    def _port_key(self, port: PortInfo) -> Tuple[str, int, str]:
        return (port.ip, port.port, port.protocol or "tcp")

    def _service(self, port: PortInfo | None) -> str | None:
        if port is None:
            return None
        return port.normalized_service()

    def _banner(self, port: PortInfo | None) -> str | None:
        if port is None:
            return None
        return port.normalized_banner()

    def _vulnerability_count(self, port: PortInfo | None) -> int | None:
        if port is None or port.vulnerabilities is None:
            return None
        return port.vulnerabilities.total_count

    def _vulnerability_max_score(self, port: PortInfo | None) -> float | None:
        if port is None or port.vulnerabilities is None:
            return None
        return port.vulnerabilities.max_score

    def _vulnerability_severity(self, port: PortInfo | None) -> str | None:
        if port is None or port.vulnerabilities is None:
            return None
        return port.vulnerabilities.severity

    def _vulnerability_summary_json(self, port: PortInfo | None) -> str | None:
        if port is None or port.vulnerabilities is None:
            return None
        return port.vulnerabilities.model_dump_json()

    def _parse_vulnerability_summary(self, raw_value: str | None) -> VulnerabilitySummary | None:
        if not raw_value:
            return None
        try:
            return VulnerabilitySummary.model_validate(json.loads(raw_value))
        except (json.JSONDecodeError, TypeError, ValidationError):
            logger.warning("Failed to parse vulnerability summary from database")
            return None

    def _parse_datetime(self, raw_value: str | None) -> datetime:
        if not raw_value:
            return datetime.now()
        try:
            return datetime.fromisoformat(raw_value)
        except ValueError:
            return datetime.now()

    def _is_port_open(self, port: PortInfo) -> bool:
        return bool(getattr(port, "is_open", True))

    def _get_scan_scope(self, port: PortInfo) -> str:
        return str(getattr(port, "scan_scope", ""))

    def _get_metadata(self, db: sqlite3.Connection, key: str) -> str | None:
        row = db.execute(
            "SELECT value FROM scan_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return None if row is None else row["value"]

    def _set_metadata(self, db: sqlite3.Connection, key: str, value: str) -> None:
        db.execute(
            """
            INSERT INTO scan_metadata (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (key, value, datetime.now().isoformat()),
        )
