"""User management (admin only): create, change role, reset password,
delete. Resets force a password change on next login."""
from __future__ import annotations

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user

from netshield.audit import log_activity
from netshield.extensions import db
from netshield.models.models import Setting, User, utcnow
from netshield.security import (generate_temp_password, hash_password,
                                admin_required)

bp = Blueprint("users", __name__)


@bp.route("/users")
@admin_required
def index():
    users = User.query.order_by(User.username).all()
    return render_template("users.html", users=users)


@bp.route("/users", methods=["POST"])
@admin_required
def create():
    username = (request.form.get("username") or "").strip()
    role = request.form.get("role", "standard")
    if not username or len(username) < 3:
        flash("Username must be at least 3 characters.", "danger")
        return redirect(url_for("settings.index"))
    if User.query.filter_by(username=username).first():
        flash("That username already exists.", "warning")
        return redirect(url_for("settings.index"))
    temp = generate_temp_password()
    digest, salt = hash_password(temp)
    user = User(username=username, password_hash=digest, salt=salt,
                role=role if role in ("admin", "standard") else "standard",
                created_at=utcnow())
    db.session.add(user)
    db.session.commit()
    Setting.set("pending_pw_change", username)
    log_activity(current_user.username,
                 f"created user {username} (role {user.role})")
    flash(f"User '{username}' created. Temporary password (shown once): "
          f"{temp}", "success")
    return redirect(url_for("settings.index"))


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@admin_required
def change_role(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    role = request.form.get("role")
    if role not in ("admin", "standard"):
        flash("Invalid role.", "danger")
        return redirect(url_for("settings.index"))
    if user.id == current_user.id and role != "admin":
        flash("You cannot demote your own account.", "danger")
        return redirect(url_for("settings.index"))
    old = user.role
    user.role = role
    db.session.commit()
    log_activity(current_user.username,
                 f"changed role of {user.username}: {old} -> {role}")
    flash(f"{user.username} is now {role}.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@admin_required
def reset_password(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    temp = generate_temp_password()
    digest, salt = hash_password(temp)
    user.password_hash = digest
    user.salt = salt
    db.session.commit()
    Setting.set("pending_pw_change", user.username)
    log_activity(current_user.username, f"reset password for {user.username}")
    flash(f"Password for '{user.username}' reset. Temporary password (shown "
          f"once): {temp}", "success")
    return redirect(url_for("settings.index"))


@bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete(user_id):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("settings.index"))
    if user.is_admin and User.query.filter_by(role="admin").count() <= 1:
        flash("Cannot delete the last administrator.", "danger")
        return redirect(url_for("settings.index"))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_activity(current_user.username, f"deleted user {username}")
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("settings.index"))
