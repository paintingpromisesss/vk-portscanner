import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple

import aiosqlite

from src.models.schemas import PortChange, PortInfo
from src.storage.database import DB_PATH

logger = logging.getLogger(__name__)


class PortRepository:
    async def save_scan_diff(self, ports: List[PortInfo]) -> List[PortChange]:
        changes: List[PortChange] = []
        observed_keys = {
            self._port_key(port) for port in ports
        }

        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            existing_rows = await self._load_existing_ports(db)

            for port in ports:
                before = existing_rows.get(self._port_key(port))
                if before is None:
                    await self._insert_current_state(db, port)
                    changes.append(PortChange(after=port, ip=port.ip, port=port.port, protocol=port.protocol))
                    continue

                if before.state_equals(port) and before.protocol == port.protocol:
                    await self._mark_seen_without_changes(db, port)
                    continue

                await self._update_current_state(db, port)
                changes.append(
                    PortChange(
                        before=before,
                        after=port,
                        ip=port.ip,
                        port=port.port,
                        protocol=port.protocol,
                    )
                )

            for key, existing_port in existing_rows.items():
                if key in observed_keys or not self._is_port_open(existing_port):
                    continue

                await self._mark_closed(db, existing_port)
                changes.append(
                    PortChange(
                        before=existing_port,
                        after=None,
                        ip=existing_port.ip,
                        port=existing_port.port,
                        protocol=existing_port.protocol,
                    )
                )

            for change in changes:
                await self._insert_change_log(db, change)

            await db.commit()

        if changes:
            logger.info("Detected %s changes after diff", len(changes))
        else:
            logger.info("No changes detected after diff")

        return changes

    async def _load_existing_ports(self, db: aiosqlite.Connection) -> Dict[Tuple[str, int, str], PortInfo]:
        cursor = await db.execute("""
            SELECT ip, port, protocol, service, banner, cve_list, discovered_at, is_open
            FROM ports
        """)
        rows = await cursor.fetchall()

        existing_ports: Dict[Tuple[str, int, str], PortInfo] = {}
        for row in rows:
            port = PortInfo(
                ip=row["ip"],
                port=row["port"],
                protocol=row["protocol"] or "tcp",
                service=row["service"],
                banner=row["banner"],
                cve_list=self._loads_cve_list(row["cve_list"]),
                discovered_at=self._parse_datetime(row["discovered_at"]),
            )
            port.__dict__["is_open"] = bool(row["is_open"])
            existing_ports[self._port_key(port)] = port

        return existing_ports

    async def _insert_current_state(self, db: aiosqlite.Connection, port: PortInfo) -> None:
        timestamp = datetime.now()
        await db.execute(
            """
            INSERT INTO ports (
                ip, port, protocol, service, banner, cve_list, is_open, discovered_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (
                port.ip,
                port.port,
                port.protocol,
                port.normalized_service(),
                port.normalized_banner(),
                self._dumps_cve_list(port.cve_list),
                port.discovered_at,
                timestamp,
            ),
        )

    async def _update_current_state(self, db: aiosqlite.Connection, port: PortInfo) -> None:
        await db.execute(
            """
            UPDATE ports
            SET service = ?, banner = ?, cve_list = ?, is_open = 1, updated_at = ?
            WHERE ip = ? AND port = ? AND protocol = ?
            """,
            (
                port.normalized_service(),
                port.normalized_banner(),
                self._dumps_cve_list(port.cve_list),
                datetime.now(),
                port.ip,
                port.port,
                port.protocol,
            ),
        )

    async def _mark_seen_without_changes(self, db: aiosqlite.Connection, port: PortInfo) -> None:
        await db.execute(
            """
            UPDATE ports
            SET is_open = 1, updated_at = ?
            WHERE ip = ? AND port = ? AND protocol = ?
            """,
            (datetime.now(), port.ip, port.port, port.protocol),
        )

    async def _mark_closed(self, db: aiosqlite.Connection, port: PortInfo) -> None:
        await db.execute(
            """
            UPDATE ports
            SET is_open = 0, updated_at = ?
            WHERE ip = ? AND port = ? AND protocol = ?
            """,
            (datetime.now(), port.ip, port.port, port.protocol),
        )

    async def _insert_change_log(self, db: aiosqlite.Connection, change: PortChange) -> None:
        await db.execute(
            """
            INSERT INTO port_changes (
                ip, port, protocol, change_type,
                before_service, before_banner, before_cve_list,
                after_service, after_banner, after_cve_list,
                changed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                change.ip,
                change.port,
                change.protocol,
                change.change_type,
                self._service(change.before),
                self._banner(change.before),
                self._dumps_cve_list(change.before.cve_list if change.before else []),
                self._service(change.after),
                self._banner(change.after),
                self._dumps_cve_list(change.after.cve_list if change.after else []),
                change.changed_at,
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

    def _dumps_cve_list(self, cve_list: List[str]) -> str:
        return json.dumps(sorted({cve.strip() for cve in cve_list if cve.strip()}), ensure_ascii=False)

    def _loads_cve_list(self, raw_value: str | None) -> List[str]:
        if not raw_value:
            return []
        try:
            value = json.loads(raw_value)
            if isinstance(value, list):
                return [str(item) for item in value]
        except json.JSONDecodeError:
            logger.warning("Failed to decode cve_list from DB, returning empty list")
        return []

    def _parse_datetime(self, raw_value: str | None) -> datetime:
        if not raw_value:
            return datetime.now()
        try:
            return datetime.fromisoformat(raw_value)
        except ValueError:
            return datetime.now()

    def _is_port_open(self, port: PortInfo) -> bool:
        return bool(getattr(port, "is_open", True))
