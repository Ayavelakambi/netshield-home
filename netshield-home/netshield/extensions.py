"""Shared Flask extension instances (initialised in the app factory)."""
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()

login_manager.login_view = "auth.login"
login_manager.login_message = "Please sign in to access NetShield Home."
login_manager.login_message_category = "warning"
