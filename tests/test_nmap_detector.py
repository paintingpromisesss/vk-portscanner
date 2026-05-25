import tempfile
import unittest
from pathlib import Path

from src.models.schemas import PortInfo
from src.scanner.nmap_detector import NmapServiceDetector


class NmapServiceDetectorTestCase(unittest.TestCase):
    def test_parse_xml_extracts_service_version_banner(self):
        payload = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.7" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="6.6.1p1" extrainfo="Ubuntu"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".xml") as temp_file:
            temp_file.write(payload)
            path = Path(temp_file.name)

        try:
            detector = NmapServiceDetector()
            ports = detector._parse_xml(path)
        finally:
            path.unlink(missing_ok=True)

        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0].service, "http")
        self.assertEqual(ports[0].banner, "Apache httpd 2.4.7 Ubuntu")
        self.assertEqual(ports[1].service, "ssh")
        self.assertEqual(ports[1].banner, "OpenSSH 6.6.1p1 Ubuntu")

    def test_should_replace_empty_or_versionless_banner(self):
        detector = NmapServiceDetector()
        detected = PortInfo(ip="127.0.0.1", port=80, service="http", banner="Apache httpd 2.4.7 Ubuntu")

        self.assertTrue(detector._should_replace(PortInfo(ip="127.0.0.1", port=80, banner=""), detected))
        self.assertTrue(
            detector._should_replace(
                PortInfo(ip="127.0.0.1", port=80, service="http", banner="HTTP/1.1 301 | Server: apache"),
                detected,
            )
        )
        self.assertFalse(
            detector._should_replace(
                PortInfo(ip="127.0.0.1", port=80, service="http", banner="nginx/1.24.0"),
                detected,
            )
        )
