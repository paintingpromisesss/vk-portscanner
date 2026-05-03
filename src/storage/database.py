import aiosqlite
import logging
import os
import sqlite3

logger = logging.getLogger(__name__)

DB_PATH = "data/scanner.db"

async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                service TEXT,
                banner TEXT,
                cve_list TEXT,
                is_open INTEGER NOT NULL DEFAULT 1,
                discovered_at TIMESTAMP,
                updated_at TIMESTAMP,
                UNIQUE(ip, port, protocol)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS port_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                change_type TEXT NOT NULL,
                before_service TEXT,
                before_banner TEXT,
                before_cve_list TEXT,
                after_service TEXT,
                after_banner TEXT,
                after_cve_list TEXT,
                changed_at TIMESTAMP NOT NULL
            )
        """)

        for statement in (
            "ALTER TABLE ports ADD COLUMN cve_list TEXT",
            "ALTER TABLE ports ADD COLUMN is_open INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE ports ADD COLUMN updated_at TIMESTAMP",
        ):
            try:
                await db.execute(statement)
            except sqlite3.OperationalError:
                pass

        await db.commit()
        logger.debug("Database initialized")
