import tempfile
import unittest
import sqlite3
from pathlib import Path

from src.models.schemas import PortInfo, VulnerabilityInfo, VulnerabilitySummary
from src.storage.database import init_db
from src.storage.repository import PortRepository


class RepositoryDiffTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "scanner.db")
        await init_db(self.db_path)
        self.repo = PortRepository(self.db_path)

    async def asyncTearDown(self):
        self.temp_dir.cleanup()

    async def test_scope_change_does_not_close_previous_ports(self):
        port = PortInfo(ip="10.0.0.1", port=80, protocol="tcp", service="http", banner="HTTP/1.1 200 OK")

        first_changes = await self.repo.save_scan_diff([port], "targets=10.0.0.0/24|ports=80")
        second_changes = await self.repo.save_scan_diff([], "targets=10.0.1.0/24|ports=443")
        third_changes = await self.repo.save_scan_diff([], "targets=10.0.1.0/24|ports=443")

        self.assertEqual(len(first_changes), 1)
        self.assertEqual(second_changes, [])
        self.assertEqual(third_changes, [])

    async def test_same_scope_missing_port_becomes_closed(self):
        port = PortInfo(ip="10.0.0.1", port=22, protocol="tcp", service="ssh", banner="OpenSSH")

        await self.repo.save_scan_diff([port], "targets=10.0.0.0/24|ports=22")
        changes = await self.repo.save_scan_diff([], "targets=10.0.0.0/24|ports=22")

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change_type, "closed")

    async def test_vulnerability_columns_are_created(self):
        with sqlite3.connect(self.db_path) as db:
            port_columns = {row[1] for row in db.execute("PRAGMA table_info(ports)").fetchall()}
            change_columns = {row[1] for row in db.execute("PRAGMA table_info(port_changes)").fetchall()}

        self.assertIn("vulnerability_summary", port_columns)
        self.assertIn("after_vulnerability_summary", change_columns)

    async def test_vulnerability_summary_is_saved_and_loaded(self):
        port = PortInfo(
            ip="10.0.0.1",
            port=80,
            protocol="tcp",
            service="http",
            banner="Server: nginx/1.24.0",
            vulnerabilities=VulnerabilitySummary(
                total_count=1,
                max_score=8.7,
                severity="HIGH",
                top=[
                    VulnerabilityInfo(
                        id="CVE-2024-0001",
                        cves=["CVE-2024-0001"],
                        score=8.7,
                    )
                ],
            ),
        )

        await self.repo.save_scan_diff([port], "targets=10.0.0.0/24|ports=80")
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        loaded = self.repo._load_existing_ports(db)
        db.close()
        saved_port = loaded[(port.ip, port.port, port.protocol)]

        self.assertIsNotNone(saved_port.vulnerabilities)
        self.assertEqual(saved_port.vulnerabilities.total_count, 1)
        self.assertEqual(saved_port.vulnerabilities.severity, "HIGH")

    async def test_vulnerability_change_creates_risk_diff(self):
        first = PortInfo(
            ip="10.0.0.1",
            port=80,
            protocol="tcp",
            service="http",
            banner="Server: nginx/1.24.0",
        )
        second = PortInfo(
            ip="10.0.0.1",
            port=80,
            protocol="tcp",
            service="http",
            banner="Server: nginx/1.24.0",
            vulnerabilities=VulnerabilitySummary(
                total_count=1,
                max_score=9.1,
                severity="CRITICAL",
                top=[VulnerabilityInfo(id="CVE-2024-0002", cves=["CVE-2024-0002"], score=9.1)],
            ),
        )

        await self.repo.save_scan_diff([first], "targets=10.0.0.0/24|ports=80")
        changes = await self.repo.save_scan_diff([second], "targets=10.0.0.0/24|ports=80")

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].change_type, "risk")
        self.assertEqual(changes[0].after.vulnerabilities.severity, "CRITICAL")
