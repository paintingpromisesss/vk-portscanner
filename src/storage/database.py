import logging
import os
import sqlite3

logger = logging.getLogger(__name__)

DB_PATH = "data/scanner.db"


async def init_db(db_path: str = DB_PATH):
    _init_db_sync(db_path)


def _init_db_sync(db_path: str = DB_PATH) -> None:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with sqlite3.connect(db_path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                service TEXT,
                banner TEXT,
                vulnerability_count INTEGER,
                vulnerability_max_score REAL,
                vulnerability_severity TEXT,
                vulnerability_summary TEXT,
                is_open INTEGER NOT NULL DEFAULT 1,
                scan_scope TEXT,
                discovered_at TIMESTAMP,
                updated_at TIMESTAMP,
                UNIQUE(ip, port, protocol)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS port_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                change_type TEXT NOT NULL,
                before_service TEXT,
                before_banner TEXT,
                after_service TEXT,
                after_banner TEXT,
                after_vulnerability_count INTEGER,
                after_vulnerability_max_score REAL,
                after_vulnerability_severity TEXT,
                after_vulnerability_summary TEXT,
                changed_at TIMESTAMP NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS scan_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP NOT NULL
            )
        """)

        port_columns = {
            row[1] for row in db.execute("PRAGMA table_info(ports)").fetchall()
        }
        migration_statements = {
            "is_open": "ALTER TABLE ports ADD COLUMN is_open INTEGER NOT NULL DEFAULT 1",
            "scan_scope": "ALTER TABLE ports ADD COLUMN scan_scope TEXT",
            "updated_at": "ALTER TABLE ports ADD COLUMN updated_at TIMESTAMP",
            "vulnerability_count": "ALTER TABLE ports ADD COLUMN vulnerability_count INTEGER",
            "vulnerability_max_score": "ALTER TABLE ports ADD COLUMN vulnerability_max_score REAL",
            "vulnerability_severity": "ALTER TABLE ports ADD COLUMN vulnerability_severity TEXT",
            "vulnerability_summary": "ALTER TABLE ports ADD COLUMN vulnerability_summary TEXT",
        }
        for column_name, statement in migration_statements.items():
            if column_name not in port_columns:
                db.execute(statement)

        change_columns = {
            row[1] for row in db.execute("PRAGMA table_info(port_changes)").fetchall()
        }
        change_migration_statements = {
            "after_vulnerability_count": "ALTER TABLE port_changes ADD COLUMN after_vulnerability_count INTEGER",
            "after_vulnerability_max_score": "ALTER TABLE port_changes ADD COLUMN after_vulnerability_max_score REAL",
            "after_vulnerability_severity": "ALTER TABLE port_changes ADD COLUMN after_vulnerability_severity TEXT",
            "after_vulnerability_summary": "ALTER TABLE port_changes ADD COLUMN after_vulnerability_summary TEXT",
        }
        for column_name, statement in change_migration_statements.items():
            if column_name not in change_columns:
                db.execute(statement)

        db.commit()
        logger.debug("Database initialized")
