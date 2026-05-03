import asyncio
import logging
import smtplib
from email.message import EmailMessage
from typing import List

from src.models.schemas import PortChange, PortInfo
from src.notifier.base import BaseNotifier

logger = logging.getLogger(__name__)

DISPLAY_CVE_LIMIT = 10


class EmailNotifier(BaseNotifier):
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        use_tls: bool,
        username: str,
        password: str,
        from_email: str,
        to_email: str,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_email = to_email

    async def notify(self, changes: List[PortChange]) -> bool:
        if not changes:
            return True

        message = self._build_message(changes)
        try:
            await asyncio.to_thread(self._send_message, message)
            logger.info("Email notification sent successfully")
            return True
        except Exception:
            logger.exception("Failed to send email notification")
            return False

    def _build_message(self, changes: List[PortChange]) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = f"Port Scanner: {len(changes)} change(s) detected"
        message["From"] = self.from_email
        message["To"] = self.to_email

        lines = ["Port Scanner detected changes:", ""]
        for change in changes:
            lines.append(self._format_change(change))
            lines.append("")

        message.set_content("\n".join(lines).strip())
        return message

    def _format_change(self, change: PortChange) -> str:
        before = self._format_state(change.before)
        after = self._format_state(change.after)
        return (
            f"[{change.change_type.upper()}] {change.ip}:{change.port}/{change.protocol}\n"
            f"Before: {before}\n"
            f"After: {after}"
        )

    def _format_state(self, port: PortInfo | None) -> str:
        if port is None:
            return "not seen"

        service = port.normalized_service()
        banner = port.normalized_banner() or "empty banner"
        cves = self._format_cves(port.normalized_cve_list())
        return f"service={service}; banner={banner}; cve={cves}"

    def _format_cves(self, cve_list: List[str]) -> str:
        if not cve_list:
            return "none"

        visible = cve_list[:DISPLAY_CVE_LIMIT]
        formatted = ", ".join(visible)
        remaining = len(cve_list) - len(visible)
        if remaining > 0:
            formatted += f" ... (+{remaining} more)"
        return formatted

    def _send_message(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as smtp:
            smtp.ehlo()
            if self.use_tls:
                smtp.starttls()
                smtp.ehlo()

            if self.username:
                smtp.login(self.username, self.password)

            smtp.send_message(message)
