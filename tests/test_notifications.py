import unittest

from src.models.schemas import PortChange, PortInfo
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
