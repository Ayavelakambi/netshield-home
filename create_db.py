"""NetShield Home — database initialisation.

Creates the schema, seeds the default groups/settings, and prompts for the
first admin account. Alternative to the auto-generated first-run admin that
the app creates when the database is empty (run.py). Use:

    python create_db.py                  # interactive prompt
    python create_db.py --username admin --password secret123
    python create_db.py --auto           # random password, printed once
    python create_db.py --reset          # drop + recreate everything
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netshield import create_app  # noqa: E402
from netshield.extensions import db as db_session  # noqa: E402
from netshield.models.models import Group, Setting, User, utcnow  # noqa: E402
from netshield.security import hash_password  # noqa: E402


def _seed_groups() -> None:
    for name, cats, kbps, start, end, days in [
        ("Kids", ["youtube", "tiktok", "gaming"], None, "21:00", "06:30",
         [0, 1, 2, 3, 4]),
        ("Guests", [], None, None, None, []),
        ("IoT", [], None, None, None, []),
        ("Trusted", [], None, None, None, []),
    ]:
        if not Group.query.filter_by(name=name).first():
            db_session.session.add(Group(
                name=name, default_blocked_categories=cats,
                default_speed_limit_kbps=kbps, bedtime_start=start,
                bedtime_end=end, bedtime_days=days))
    db_session.session.commit()


def _seed_settings() -> None:
    from netshield.extensions import db as _db
    defaults = {
        "scan_interval": 60,
        "history_retention_days": 90,
        "data_threshold_mb": 0,
        "webhook_url": "", "discord_webhook": "", "telegram_token": "",
        "telegram_chat_id": "", "notify_new_device": False,
        "notify_wireless": False, "notify_data_threshold": False,
    }
    for key, value in defaults.items():
        if Setting.get(key, "UNSET") == "UNSET":
            Setting.set(key, value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", default=None, help="admin username")
    parser.add_argument("--password", default=None,
                        help="admin password (not shown in process list "
                             "if omitted)")
    parser.add_argument("--auto", action="store_true",
                        help="generate a random admin password, print once")
    parser.add_argument("--reset", action="store_true",
                        help="drop all tables first (destructive)")
    args = parser.parse_args()

    # auto_admin=False: create_db.py owns first-admin creation (the app
    # factory only auto-generates one when run.py is used directly).
    app = create_app(test_config={"TESTING": True}, auto_admin=False,
                     start_background=False)

    with app.app_context():
        if args.reset:
            db_session.drop_all()
            db_session.create_all()
            print("Database recreated from scratch.")
        else:
            db_session.create_all()

        _seed_groups()
        _seed_settings()

        if User.query.count() > 0:
            print("Users already exist — no admin created. (Use "
                  "--reset to wipe the database.)")
            return 0

        username = args.username
        password = args.password
        if args.auto:
            username = username or "admin"
            password = secrets.token_urlsafe(10)
        else:
            while not username:
                username = input("Admin username [admin]: ").strip() or "admin"
            if password is None:
                while True:
                    p1 = getpass.getpass("Admin password: ")
                    p2 = getpass.getpass("Confirm password: ")
                    if p1 == p2 and len(p1) >= 8:
                        password = p1
                        break
                    print("Passwords must match and be at least 8 chars.")

        digest, salt = hash_password(password)
        admin = User(username=username, password_hash=digest, salt=salt,
                     role="admin", created_at=utcnow())
        db_session.session.add(admin)
        db_session.session.commit()
        print()
        print("=" * 56)
        print("  NetShield Home database initialised.")
        print(f"  Admin account : {username}")
        print(f"  Password      : {'(as entered)' if args.password or not args.auto else password}")
        print("  DB file       : data/netshield.db")
        print("  Next step     : python run.py")
        print("=" * 56)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
