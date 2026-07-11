"""
extensions.py — Shared Flask extension instances.

Kept in their own module (rather than created inside app.py) so models.py,
orchestrator.py, and the blueprints can all import `db` and `login_manager`
without circular-import problems.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
