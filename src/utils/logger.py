import logging
import sys
import os

def setup_logging(level: int = logging.INFO, log_file: str = "scanner.log") -> None:
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    os.makedirs("logs", exist_ok=True)
    file_handler = logging.FileHandler(f"logs/{log_file}", encoding="utf-8")
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    logging.debug("Логирование успешно инициализировано.")
