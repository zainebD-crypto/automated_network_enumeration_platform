"""
team.py — Team management page (admin-only): view, add, and remove
pentester accounts. All actual mutation logic lives in api.py's /api/team
endpoints; this just renders the page shell.
"""
from flask import Blueprint, render_template, abort
from flask_login import login_required, current_user

team_bp = Blueprint("team", __name__)


@team_bp.route("/team")
@login_required
def team_page():
    if not current_user.is_admin:
        abort(403)
    return render_template("team.html")
