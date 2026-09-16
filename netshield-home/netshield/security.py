"""Password hashing (PBKDF2-SHA256, per-user random salt) and role decorators.

Passwords are never stored in plaintext and never logged anywhere in this
project. Each user gets a fresh random salt; verification uses a
constant-time comparison.
"""
from __future__ import annotations

import hashlib
import secrets
from functools import wraps

from flask import abort, redirect, request, url_for
from flask_login import current_user

PBKDF2_ITERATIONS = 200_000


def hash_password(password: str) -> tuple[str, str]:
    """Return (password_hash, salt_hex)."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()
    return digest, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()
    return secrets.compare_digest(digest, stored_hash)


def generate_temp_password(length: int = 12) -> str:
    """Readable random password for admin-created / reset accounts."""
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def admin_required(fn):
    """Blueprint decorator: admin-only route (403 for standard users)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.url))
        if not current_user.is_admin:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper
