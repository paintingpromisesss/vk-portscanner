
import asyncio
import json
import logging
import os
import tempfile
from typing import List, Optional

from src.models.schemas import PortInfo

logger = logging.getLogger(__name__)

class MasscanRunner:
    def __init__(self, executable_path: str = "masscan", rate: int = 1000, wait: int = 5):
        self.executable_path = executable_path
        self.rate = rate
        self.wait = wait

    async def scan(self, targets: str, ports: str) -> Optional[List[PortInfo]]:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
            temp_filename = temp_file.name
        try:
            cmd = [
                self.executable_path,
                self._normalize_csv(targets),
                "-p",
                self._normalize_csv(ports),
                "--rate",
                str(self.rate),
                "-oJ",
                temp_filename,
                "--wait",
                str(self.wait),
            ]

            logger.info(f"running masscan: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"masscan failed: {stderr.decode()}")
                return None

            results = []
            if os.path.exists(temp_filename) and os.path.getsize(temp_filename) > 0:
                with open(temp_filename,  'r') as f:
                    try:
                        data = json.load(f)
                        for item in data:
                            ip = item.get("ip")
                            for port_info in item.get("ports", []):
                                results.append(PortInfo(
                                    ip=ip,
                                    port=int(port_info.get("port")),
                                    protocol=port_info.get("proto", "tcp")
                                ))
                    except json.JSONDecodeError:
                        logger.error(f"failed to parse masscan output: {stderr.decode()}")
            logger.info(f"masscan completed, found {len(results)} results")
            return results
        finally:
            if os.path.exists(temp_filename):
                os.remove(temp_filename)

    def _normalize_csv(self, value: str) -> str:
        return ",".join(part.strip() for part in value.split(",") if part.strip())
