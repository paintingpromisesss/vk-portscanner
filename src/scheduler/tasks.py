import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from src.config.config import Config
from src.models.schemas import PortChange, PortInfo, VulnerabilityInfo, VulnerabilitySummary
from src.grabber.grabber import BannerGrabber
from src.notifier.email import EmailNotifier
from src.notifier.telegram import TelegramNotifier
from src.scanner.masscan_runner import MasscanRunner
from src.scanner.nmap_detector import NmapServiceDetector
from src.storage.repository import PortRepository
from src.vulners.client import VulnersClient

logger = logging.getLogger(__name__)

async def run_pipeline(config: Config):
    logger.info("=== Scanning pipeline started ===")

    scanner = MasscanRunner(rate=config.scanner.rate, wait=config.scanner.wait)
    raw_ports = await scanner.scan(config.scanner.targets, config.scanner.ports)
    if raw_ports is None:
        logger.warning("Masscan scan failed. Skipping diff for this run.")
        return

    grabber = BannerGrabber(timeout=config.grabber.timeout, concurrency_limit=config.grabber.concurrency_limit)
    processed_ports = await grabber.process_targets(raw_ports)

    service_detector = NmapServiceDetector(
        enabled=config.service_detector.enabled,
        timeout=config.service_detector.timeout,
    )
    processed_ports = await service_detector.enrich_ports(processed_ports)

    vulners_client = VulnersClient(
        enabled=config.vulners.enabled,
        api_key=config.vulners.api_key,
        max_results_per_service=config.vulners.max_results_per_service,
    )
    processed_ports = await vulners_client.enrich_ports(processed_ports)

    repo = PortRepository()
    changes = await repo.save_scan_diff(
        processed_ports,
        scan_scope=build_scan_scope(config),
    )

    if not changes:
        logger.info("No changes found. Exiting.")
        return

    logger.info("Found %s changes.", len(changes))
    await send_notifications(config, changes)

    logger.info("=== Scanning pipeline completed ===")

async def send_test_notifications(config: Config):
    logger.info("Sending test notifications...")
    test_change = PortChange(
        ip="127.0.0.1",
        port=443,
        protocol="tcp",
        before=PortInfo(
            ip="127.0.0.1",
            port=443,
            protocol="tcp",
            service="https",
            banner="nginx 1.24.0",
            discovered_at=datetime.now(),
        ),
        after=PortInfo(
            ip="127.0.0.1",
            port=443,
            protocol="tcp",
            service="ssl/http",
            banner="nginx 1.24.0 OpenSSL",
            vulnerabilities=VulnerabilitySummary(
                total_count=1,
                max_score=8.7,
                severity="HIGH",
                top=[
                    VulnerabilityInfo(
                        id="CVE-2024-6387",
                        cves=["CVE-2024-6387"],
                        title="OpenSSH regreSSHion remote code execution",
                        score=8.7,
                        href="https://vulners.com/cve/CVE-2024-6387",
                        description="Signal check for high-risk vulnerability notification formatting",
                    )
                ],
            ),
            discovered_at=datetime.now(),
        ),
        changed_at=datetime.now(),
    )
    await send_notifications(config, [test_change])

async def send_notifications(config: Config, changes: list[PortChange]):
    if not config.email.enabled and not config.telegram.enabled:
        logger.warning("All notification channels are disabled. Nothing to send.")
        return

    if config.email.enabled:
        logger.info("Sending email notification...")
        notifier = EmailNotifier(
            smtp_host=config.email.smtp_host,
            smtp_port=config.email.smtp_port,
            use_tls=config.email.use_tls,
            username=config.email.username,
            password=config.email.password,
            from_email=config.email.from_email,
            to_email=config.email.to_email,
        )
        await notifier.notify(changes)

    if config.telegram.enabled:
        logger.info("Sending Telegram notification...")
        notifier = TelegramNotifier(
            bot_token=config.telegram.bot_token,
            chat_id=config.telegram.chat_id
        )

        await notifier.notify(changes)

def build_scan_scope(config: Config) -> str:
    normalized_targets = ",".join(sorted(part.strip() for part in config.scanner.targets.split(",") if part.strip()))
    normalized_ports = ",".join(sorted(part.strip() for part in config.scanner.ports.split(",") if part.strip()))
    return f"targets={normalized_targets}|ports={normalized_ports}"

def setup_scheduler(config: Config) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        run_pipeline,
        'interval',
        minutes=config.scheduler.interval_minutes,
        args=[config]
    )
    return scheduler
