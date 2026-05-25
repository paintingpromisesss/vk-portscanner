import unittest

from src.models.schemas import PortInfo
from src.vulners.client import VulnersClient


class FakeAudit:
    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.calls = []

    def software(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        return self.response


class FakeVulnersApi:
    def __init__(self, response=None, exc=None):
        self.audit = FakeAudit(response=response, exc=exc)


class VulnersClientTestCase(unittest.IsolatedAsyncioTestCase):
    def test_extracts_nginx_from_http_banner(self):
        client = VulnersClient(api_key="key", enabled=True)
        port = PortInfo(ip="127.0.0.1", port=80, service="http", banner="Server: nginx/1.24.0")

        software = client.extract_software(port)

        self.assertIsNotNone(software)
        self.assertEqual(software.product, "nginx")
        self.assertEqual(software.version, "1.24.0")

    def test_extracts_apache_from_banner(self):
        client = VulnersClient(api_key="key", enabled=True)
        port = PortInfo(ip="127.0.0.1", port=80, service="http", banner="Apache/2.4.58")

        software = client.extract_software(port)

        self.assertIsNotNone(software)
        self.assertEqual(software.product, "apache httpd")
        self.assertEqual(software.version, "2.4.58")

    def test_extracts_openssh_from_banner(self):
        client = VulnersClient(api_key="key", enabled=True)
        port = PortInfo(ip="127.0.0.1", port=22, service="ssh", banner="SSH-2.0-OpenSSH_9.0")

        software = client.extract_software(port)

        self.assertIsNotNone(software)
        self.assertEqual(software.product, "openssh")
        self.assertEqual(software.version, "9.0")

    def test_unparseable_banner_returns_none(self):
        client = VulnersClient(api_key="key", enabled=True)
        port = PortInfo(ip="127.0.0.1", port=12345, service="unknown", banner="hello")

        self.assertIsNone(client.extract_software(port))

    async def test_maps_audit_response_into_summary(self):
        response = [
            {
                "vulnerabilities": [
                    {
                        "id": "CVE-LOW",
                        "cvelist": ["CVE-2024-0001"],
                        "title": "Low risk",
                        "href": "https://vulners.com/cve/CVE-LOW",
                        "short_description": "Low issue",
                        "ai_score": {"value": 3.0},
                    },
                    {
                        "id": "CVE-HIGH",
                        "cvelist": ["CVE-2024-0002"],
                        "title": "High risk",
                        "href": "https://vulners.com/cve/CVE-HIGH",
                        "short_description": "High issue",
                        "ai_score": {"value": 8.7},
                    },
                ]
            }
        ]
        api = FakeVulnersApi(response=response)
        client = VulnersClient(api_key="key", enabled=True, max_results_per_service=1, api=api)
        port = PortInfo(ip="127.0.0.1", port=80, service="http", banner="Server: nginx/1.24.0")

        enriched = await client.enrich_port(port)

        self.assertIsNotNone(enriched.vulnerabilities)
        self.assertEqual(enriched.vulnerabilities.total_count, 2)
        self.assertEqual(enriched.vulnerabilities.severity, "HIGH")
        self.assertEqual(enriched.vulnerabilities.top[0].id, "CVE-HIGH")
        self.assertEqual(len(enriched.vulnerabilities.top), 1)
        self.assertEqual(api.audit.calls[0]["catalog"], "extended")

    async def test_api_error_keeps_port_unchanged(self):
        api = FakeVulnersApi(exc=RuntimeError("boom"))
        client = VulnersClient(api_key="key", enabled=True, api=api)
        port = PortInfo(ip="127.0.0.1", port=80, service="http", banner="Server: nginx/1.24.0")

        enriched = await client.enrich_port(port)

        self.assertIs(enriched, port)
        self.assertIsNone(enriched.vulnerabilities)
