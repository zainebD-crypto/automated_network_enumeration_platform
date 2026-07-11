"""
scans.py — HTML page routes: scan history ("My Scans") and scan detail view.

All actual data comes from api.py's JSON endpoints, polled client-side —
these routes just render the page shells.
"""
from flask import Blueprint, render_template
from flask_login import login_required

from models import Scan

scans_bp = Blueprint("scans", __name__)


@scans_bp.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@scans_bp.route("/analytics")
@login_required
def analytics_page():
    return render_template("analytics.html")


@scans_bp.route("/vulnerabilities")
@login_required
def vulnerabilities_page():
    return render_template("vulnerabilities.html")


@scans_bp.route("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template("scan_detail.html", scan=scan)
