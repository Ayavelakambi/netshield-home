"""Authentication: login, logout, forced first-login password change."""
from __future__ import annotations

from flask import (Blueprint, flash, redirect, render_template, request, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from netshield.audit import log_activity
from netshield.extensions import db
from netshield.models.models import Setting, User, utcnow
from netshield.security import hash_password, verify_password

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        # Generic error: never reveal whether the username exists.
        if user is None or not verify_password(password, user.password_hash,
                                               user.salt):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")
        login_user(user)
        user.last_login = utcnow()
        db.session.commit()
        log_activity(user.username, "login")
        if Setting.get("pending_pw_change") == user.username:
            flash("You must change your password before continuing.", "warning")
            return redirect(url_for("auth.change_password"))
        next_url = request.args.get("next")
        if next_url and next_url.startswith("/"):
            return redirect(next_url)
        return redirect(url_for("dashboard.index"))
    return render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    log_activity(current_user.username, "logout")
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    forced = Setting.get("pending_pw_change") == current_user.username
    if request.method == "POST":
        current_pw = request.form.get("current") or ""
        new_pw = request.form.get("new") or ""
        confirm = request.form.get("confirm") or ""
        if not verify_password(current_pw, current_user.password_hash,
                               current_user.salt):
            flash("Current password is incorrect.", "danger")
        elif len(new_pw) < 8:
            flash("New password must be at least 8 characters.", "danger")
        elif new_pw != confirm:
            flash("New passwords do not match.", "danger")
        else:
            digest, salt = hash_password(new_pw)
            current_user.password_hash = digest
            current_user.salt = salt
            db.session.commit()
            if forced:
                Setting.set("pending_pw_change", None)
            log_activity(current_user.username, "changed own password")
            flash("Password updated.", "success")
            return redirect(url_for("dashboard.index"))
    return render_template("change_password.html", forced=forced)
