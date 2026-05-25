import unittest

from src.models.schemas import PortChange, PortInfo, VulnerabilityInfo, VulnerabilitySummary
from src.notifier.email import EmailNotifier
from src.notifier.telegram import TelegramNotifier


class NotificationsTestCase(unittest.TestCase):
    def test_telegram_formats_service_and_banner(self):
        notifier = TelegramNotifier.__new__(TelegramNotifier)
        port = PortInfo(
            ip="127.0.0.1",
            port=443,
            service="ssl/http",
            banner="nginx",
        )

        formatted = notifier._format_state(port)

        self.assertIn("service=ssl/http", formatted)
        self.assertIn("banner=nginx", formatted)
        self.assertIn("cve=none", formatted)

    def test_email_uses_before_after_format(self):
        notifier = EmailNotifier(
            smtp_host="smtp.example.com",
            smtp_port=587,
            use_tls=True,
            username="user",
            password="pass",
            from_email="from@example.com",
            to_email="to@example.com",
        )
        change = PortChange(
            ip="127.0.0.1",
            port=22,
            protocol="tcp",
            before=PortInfo(ip="127.0.0.1", port=22, service="ssh", banner="OpenSSH"),
            after=PortInfo(ip="127.0.0.1", port=22, service="ssh", banner="OpenSSH 9.0"),
        )

        formatted = notifier._format_change(change)

        self.assertIn("Before:", formatted)
        self.assertIn("After:", formatted)

    def test_telegram_includes_vulnerability_risk(self):
        notifier = TelegramNotifier.__new__(TelegramNotifier)
        port = PortInfo(
            ip="127.0.0.1",
            port=443,
            service="https",
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
                        href="https://vulners.com/cve/CVE-2024-0001",
                    )
                ],
            ),
        )

        formatted = notifier._format_state(port)

        self.assertIn("risk=HIGH", formatted)
        self.assertIn("CVE-2024-0001", formatted)

    def test_email_includes_vulnerability_risk(self):
        notifier = EmailNotifier(
            smtp_host="smtp.example.com",
            smtp_port=587,
            use_tls=True,
            username="user",
            password="pass",
            from_email="from@example.com",
            to_email="to@example.com",
        )
        port = PortInfo(
            ip="127.0.0.1",
            port=443,
            service="https",
            banner="Server: nginx/1.24.0",
            vulnerabilities=VulnerabilitySummary(
                total_count=1,
                max_score=9.1,
                severity="CRITICAL",
                top=[VulnerabilityInfo(id="CVE-2024-0002", cves=["CVE-2024-0002"], score=9.1)],
            ),
        )

        formatted = notifier._format_state(port)

        self.assertIn("risk=CRITICAL", formatted)
        self.assertIn("CVE-2024-0002", formatted)

    def test_telegram_titles_vulnerability_delta_as_risk(self):
        notifier = TelegramNotifier.__new__(TelegramNotifier)
        change = PortChange(
            ip="127.0.0.1",
            port=22,
            protocol="tcp",
            before=PortInfo(ip="127.0.0.1", port=22, service="ssh", banner="OpenSSH_9.0"),
            after=PortInfo(
                ip="127.0.0.1",
                port=22,
                service="ssh",
                banner="OpenSSH_9.0",
                vulnerabilities=VulnerabilitySummary(
                    total_count=1,
                    max_score=9.0,
                    severity="CRITICAL",
                    top=[VulnerabilityInfo(id="CVE-2024-0004", cves=["CVE-2024-0004"], score=9.0)],
                ),
            ),
        )

        formatted = notifier._format_change(change)

        self.assertIn("RISK", formatted)
        self.assertIn("CVE-2024-0004", formatted)
