"""
auth.py — Authentication blueprint for the ANCScan platform:
login/logout plus a self-service password reset flow.

Account CREATION is deliberately NOT self-service here -- see team.py.
This is a pentest platform; letting anyone who reaches the login page
create their own account on a tool that can enumerate the network is not
a good default. New pentester accounts are added by an existing admin
from the Team page instead.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required

from extensions import db
from models import User
from mail_utils import send_email

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            next_url = request.args.get("next")
            return redirect(next_url or url_for("scans.dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter(db.func.lower(User.email) == email).first() if email else None

        # Same message either way -- don't leak whether an email is registered.
        generic_msg = "If an account with that email exists, password reset instructions have been sent."

        if user:
            token = user.generate_reset_token()
            db.session.commit()
            reset_url = url_for("auth.reset_password", token=token, _external=True)
            sent = send_email(
                user.email,
                "ANCScan password reset",
                f"A password reset was requested for your ANCScan account.\n\n"
                f"Reset your password here (expires in 1 hour):\n{reset_url}\n\n"
                f"If you didn't request this, you can ignore this email.",
            )
            if not sent:
                # No SMTP configured -- dev-mode fallback so the flow stays
                # testable. A real deployment should configure SMTP so this
                # link goes to the account owner's actual inbox, not the screen.
                flash(f"[DEV MODE — no SMTP configured] Reset link: {reset_url}", "info")

        flash(generic_msg, "success")
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.verify_reset_token(token):
        flash("This password reset link is invalid or has expired.", "error")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("reset_password.html", token=token)
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("reset_password.html", token=token)

        user.set_password(password)
        user.clear_reset_token()
        db.session.commit()
        flash("Password updated. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", token=token)
