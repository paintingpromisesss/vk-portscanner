import html
import logging
from typing import List

from aiogram import Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types.link_preview_options import LinkPreviewOptions

from src.models.schemas import PortChange, PortInfo
from src.notifier.base import BaseNotifier

logger = logging.getLogger(__name__)

TELEGRAM_MESSAGE_LIMIT = 4096
TELEGRAM_MESSAGE_SAFE_LIMIT = 3900


class TelegramNotifier(BaseNotifier):
    def __init__(self, bot_token: str, chat_id: str):
        self.chat_id = chat_id
        self.bot = Bot(
            token=bot_token,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        )

    async def notify(self, changes: List[PortChange]) -> bool:
        if not changes:
            return True

        chunks = self._build_message_chunks(changes)

        try:
            for chunk in chunks:
                await self.bot.send_message(
                    chat_id=self.chat_id,
                    text=chunk,
                    link_preview_options=LinkPreviewOptions(is_disabled=True),
                )
            logger.info("Sent %s Telegram message chunk(s)", len(chunks))
            return True
        except Exception as exc:
            logger.error("Failed to send Telegram message: %s", exc)
            return False
        finally:
            await self.bot.session.close()

    def _build_message_chunks(self, changes: List[PortChange]) -> List[str]:
        header = "<b>Port Scanner: changes detected</b>"
        chunks: List[str] = []
        current_chunk = header

        for change in changes:
            block = self._format_change(change)
            candidate = f"{current_chunk}\n\n{block}" if current_chunk else block
            if len(candidate) > TELEGRAM_MESSAGE_SAFE_LIMIT:
                chunks.append(current_chunk)
                current_chunk = f"{header}\n\n{block}"
            else:
                current_chunk = candidate

        if current_chunk:
            chunks.append(current_chunk)

        return [chunk[:TELEGRAM_MESSAGE_LIMIT] for chunk in chunks]

    def _format_change(self, change: PortChange) -> str:
        before_state = self._format_state(change.before)
        after_state = self._format_state(change.after)
        title = self._change_title(change)
        target = f"<code>{html.escape(change.ip)}:{change.port}/{html.escape(change.protocol)}</code>"
        return (
            f"{title}\n"
            f"<b>Target:</b> {target}\n"
            f"<b>Before:</b> <code>{before_state}</code>\n"
            f"<b>After:</b> <code>{after_state}</code>"
        )

    def _change_title(self, change: PortChange) -> str:
        titles = {
            "new": "<b>NEW</b>",
            "updated": "<b>UPDATED</b>",
            "closed": "<b>CLOSED</b>",
            "risk": "<b>RISK</b>",
        }
        return titles.get(change.change_type, "<b>CHANGED</b>")

    def _format_state(self, port: PortInfo | None) -> str:
        if port is None:
            return "not seen"

        service = self._clean_value(port.normalized_service())
        banner = self._clean_value(port.normalized_banner() or "empty banner")
        risk = self._format_risk(port)
        if risk:
            return f"service={service}; banner={banner}; {risk}"
        return f"service={service}; banner={banner}"

    def _format_risk(self, port: PortInfo) -> str:
        summary = port.vulnerabilities
        if summary is None or summary.total_count <= 0:
            return "cve=none"

        score = "unknown" if summary.max_score is None else f"{summary.max_score:.1f}"
        cves = []
        refs = []
        for vulnerability in summary.top[:3]:
            cves.extend(vulnerability.cves or [vulnerability.id])
            if vulnerability.href:
                refs.append(vulnerability.href)

        cve_text = ",".join(dict.fromkeys(cves[:3])) or "none"
        ref_text = ",".join(refs[:2])
        risk = (
            f"risk={self._clean_value(summary.severity)} "
            f"score={self._clean_value(score)} "
            f"count={summary.total_count} "
            f"cve={self._clean_value(cve_text)}"
        )
        if ref_text:
            risk = f"{risk} refs={self._clean_value(ref_text)}"
        return risk

    def _clean_value(self, value: str) -> str:
        trimmed = value.strip()[:180]
        if not trimmed:
            trimmed = "empty"
        return html.escape(trimmed)
