import argparse
import asyncio
import logging

from src.utils.logger import setup_logging
from src.config.config import load_config
from src.storage.database import init_db
from src.scheduler.tasks import send_test_notifications, setup_scheduler, run_pipeline

setup_logging(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VK PortScanner")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config file")
    parser.add_argument(
        "--test-notifications",
        action="store_true",
        help="Send test notifications without running a scan",
    )
    return parser.parse_args(argv)

async def main():
    logger.info("PortScanner initalizing...")
    args = parse_args()

    config = load_config(args.config)

    await init_db()

    if args.test_notifications:
        await send_test_notifications(config)
        return

    scheduler = setup_scheduler(config)
    scheduler.start()
    logger.info(f"Scheduler started. Interval: {config.scheduler.interval_minutes} minutes")

    await run_pipeline(config)

    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("PortScanner stopped by user (Ctrl+C).")
