# src/database/user_repository.py

import hashlib
from database.db import get_connection


def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(username, password, role):
    conn = get_connection()

    conn.execute(
        "INSERT INTO users(username,password_hash,role) VALUES (?,?,?)",
        (username, hash_password(password), role)
    )

    conn.commit()
    conn.close()


def authenticate(username, password):
    conn = get_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    ).fetchone()

    conn.close()

    if not user:
        return None

    if user["password_hash"] == hash_password(password):
        return user

    return None