# src/database/user_repository.py

import hashlib
from database.db import get_connection


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate(username: str, password: str):
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if not user:
        return None
    if user["password_hash"] == hash_password(password):
        return dict(user)
    return None


def get_user_by_username(username: str):
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def save_signature_hash(username: str, signature_hash: str) -> None:
    """Guarda el hash SHA-256 de la firma visual de referencia."""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET signature_hash = ? WHERE username = ?",
        (signature_hash, username)
    )
    conn.commit()
    conn.close()


def get_signature_hash(username: str) -> str | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT signature_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return row["signature_hash"] if row else None


def save_face_template(username: str, face_hash: str) -> None:
    """Guarda el hash SHA-256 del template dHash facial del notario."""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET face_template = ? WHERE username = ?",
        (face_hash, username)
    )
    conn.commit()
    conn.close()


def get_face_template(username: str) -> str | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT face_template FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return row["face_template"] if row else None