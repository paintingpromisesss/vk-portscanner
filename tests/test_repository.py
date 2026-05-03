import tempfile
import unittest
from pathlib import Path

from src.models.schemas import PortInfo
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
