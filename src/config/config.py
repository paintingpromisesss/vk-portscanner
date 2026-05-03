import yaml
import logging
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class ScannerConfig(BaseModel):
    targets: str
    ports: str
    rate: int

class GrabberConfig(BaseModel):
    timeout: int
    concurrency_limit: int

class VulnCheckerConfig(BaseModel):
    timeout: int
    concurrency_limit: int

class TelegramConfig(BaseModel):
    enabled: bool
    bot_token: str
    chat_id: str

class EmailConfig(BaseModel):
    enabled: bool = False
    smtp_host: str
    smtp_port: int = 587
    use_tls: bool = True
    username: str
    password: str
    from_email: str
    to_email: str

class SchedulerConfig(BaseModel):
    interval_minutes: int

class Config(BaseModel):
    scanner: ScannerConfig
    grabber: GrabberConfig
    vuln_checker: VulnCheckerConfig
    telegram: TelegramConfig
    email: EmailConfig
    scheduler: SchedulerConfig

def load_config(file_path: str = "config.yaml") -> Config:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return Config(**data)

    except FileNotFoundError:
        logger.critical(f"Config file not found: {file_path}")
        raise
    except Exception as e:
        logger.critical(f"Error loading config: {e}")
        raise
