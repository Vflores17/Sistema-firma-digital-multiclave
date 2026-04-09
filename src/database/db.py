# src/database/db.py

import sqlite3
import hashlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH  = BASE_DIR / "database.sqlite"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def init_db():
    conn = get_connection()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        username       TEXT UNIQUE NOT NULL,
        password_hash  TEXT NOT NULL,
        role           TEXT NOT NULL,
        signature_hash TEXT,
        face_template  TEXT,
        public_key     TEXT
    )
    """)

    # Migración: agrega columnas si la tabla ya existía sin ellas
    existing_cols = [
        row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()
    ]
    for col in ("signature_hash", "face_template", "public_key"):
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")

    conn.commit()

    # ── Seed admin ───────────────────────────────────────────────
    if not conn.execute(
        "SELECT id FROM users WHERE username = ?", ("admin",)
    ).fetchone():
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            ("admin", _hash_password("admin1234"), "ADMIN")
        )
        conn.commit()

    conn.close()