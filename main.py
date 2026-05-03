import asyncio
import logging

from src.utils.logger import setup_logging
from src.config.config import load_config
from src.storage.database import init_db
from src.scheduler.tasks import setup_scheduler, run_pipeline

setup_logging(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    logger.info("PortScanner initalizing...")

    config = load_config()

    await init_db()

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
