"""
app.py — ANCScan platform entry point.

Run with:  python3 app.py

First run creates ancscan.db (SQLite) next to this file and seeds a
default admin account — the console will print the generated credentials.
CHANGE THE DEFAULT PASSWORD before exposing this beyond localhost.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask

from extensions import db, login_manager
from models import User
import orchestrator


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("ANCSCAN_SECRET_KEY", "dev-only-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "ancscan.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["REPORT_DIR"] = os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "output")
    )

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from auth import auth_bp
    from scans import scans_bp
    from api import api_bp
    from team import team_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(team_bp)

    with app.app_context():
        db.create_all()
        _seed_default_admin()

    orchestrator.init_app(app)

    return app


def _seed_default_admin():
    if User.query.count() == 0:
        admin = User(username="admin", email="admin@ancscan.local", is_admin=True)
        admin.set_password("changeme")
        db.session.add(admin)
        db.session.commit()
        print("=" * 60)
        print("[*] Created default admin account:")
        print("      username: admin")
        print("      password: changeme")
        print("      email:    admin@ancscan.local")
        print("[*] CHANGE THIS before exposing the app beyond localhost.")
        print("=" * 60)


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
