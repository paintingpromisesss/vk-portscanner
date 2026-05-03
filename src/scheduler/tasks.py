import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from src.config.config import Config
from src.grabber.grabber import BannerGrabber
from src.notifier.email import EmailNotifier
from src.notifier.telegram import TelegramNotifier
from src.scanner.masscan_runner import MasscanRunner
from src.scanner.vuln_checker import VulnChecker
from src.storage.repository import PortRepository

logger = logging.getLogger(__name__)

async def run_pipeline(config: Config):
    logger.info("=== Scanning pipeline started ===")

    scanner = MasscanRunner(rate=config.scanner.rate)
    raw_ports = await scanner.scan(config.scanner.targets, config.scanner.ports)
    if raw_ports is None:
        logger.warning("Masscan scan failed. Skipping diff for this run.")
        return

    grabber = BannerGrabber(timeout=config.grabber.timeout, concurrency_limit=config.grabber.concurrency_limit)
    processed_ports = await grabber.process_targets(raw_ports)

    vuln_checker = VulnChecker(concurrency_limit=config.vuln_checker.concurrency_limit, timeout=config.vuln_checker.timeout)
    processed_ports_with_cve = await vuln_checker.check_vulnerabilities(processed_ports)

    repo = PortRepository()
    changes = await repo.save_scan_diff(processed_ports_with_cve)

    if not changes:
        logger.info("No changes found. Exiting.")
        return

    logger.info("Found %s changes.", len(changes))

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

    logger.info("=== Scanning pipeline completed ===")

def setup_scheduler(config: Config) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        run_pipeline,
        'interval',
        minutes=config.scheduler.interval_minutes,
        args=[config]
    )
    return scheduler
