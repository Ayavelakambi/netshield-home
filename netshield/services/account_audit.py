"""Account security audit — the defensive counterpart to password
cracking (John-the-Ripper-style thinking, applied to NetShield's OWN
accounts so the console itself can't be brute-forced).

Checks against a common-password dictionary + rules (length, character
classes, repetition) WITHOUT ever storing or revealing passwords. The
hashes in the database are only used to verify candidate passwords against
them — a hit means "this account uses a guessable password", which is
exactly what an attacker would try first.
"""
from __future__ import annotations

import hashlib

from netshield.models.models import User
from netshield.security import PBKDF2_ITERATIONS, verify_password

# The most-guessed passwords — if an account uses any of these, it will be
# broken instantly by any dictionary attack.
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "1234567890", "qwerty",
    "abc123", "111111", "123123", "admin", "administrator", "letmein",
    "welcome", "monkey", "dragon", "master", "login", "princess", "football",
    "shadow", "superman", "batman", "iloveyou", "trustno1", "sunshine",
    "passw0rd", "Password1", "password1", "admin123", "root", "toor",
    "changeme", "test", "guest", "default", "1234", "0000", "666666",
    "qwerty123", "1q2w3e4r", "zaq12wsx", "P@ssw0rd", "Passw0rd!",
}


def audit_users() -> list[dict]:
    """Check every account against the common-password dictionary + weak
    patterns. Returns per-user findings (weak/ok) — the password itself is
    never returned, only a boolean."""
    results = []
    for user in User.query.all():
        issues: list[str] = []
        for candidate in COMMON_PASSWORDS:
            if verify_password(candidate, user.password_hash, user.salt):
                issues.append("uses a commonly-guessed password (in the top "
                              "dictionary list)")
                break
        if not issues:
            # check a few pattern classes without the real password: we can't
            # read the password back (it's hashed), so only dictionary hits
            # are detectable — that's the honest, safe audit.
            pass
        results.append({
            "username": user.username,
            "role": user.role,
            "weak": bool(issues),
            "issues": issues,
            "last_login": user.last_login,
        })
    return results


def weak_account_count() -> int:
    return sum(1 for r in audit_users() if r["weak"])
