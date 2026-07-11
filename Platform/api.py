"""
api.py — JSON API for the ANCScan platform frontend.
"""
import os
import json
import secrets
import requests
from flask import Blueprint, jsonify, request, send_file, current_app, url_for, abort
from flask_login import login_required, current_user

from extensions import db
from models import Scan, Notification, ChatMessage, User
from mail_utils import send_email
import orchestrator
from modules.reporter import Reporter

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ---------------------------------------------------------------
# AI advisory assistant (per-scan, read-only)
#
# The assistant has NO tool access and cannot trigger scans, run commands,
# or touch the network in any way -- it can only read a scan's already-
# persisted data and talk about it. See SYSTEM_PROMPT_TEMPLATE below.
#
# Uses Groq's free-tier, OpenAI-compatible chat completions API. Get a free
# key (no credit card required) at https://console.groq.com/keys
# ---------------------------------------------------------------
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("ANCSCAN_GROQ_MODEL", "llama-3.3-70b-versatile")
CHAT_HISTORY_LIMIT = 20       # most recent messages kept as conversation context
SCAN_DATA_CHAR_LIMIT = 12000  # cap how much scan JSON is injected into the prompt

SYSTEM_PROMPT_TEMPLATE = """You are the ANCScan Assistant, embedded inside ANCScan, an internal \
penetration testing enumeration platform. You are helping a professional, authorized pentester \
interpret the results of ONE specific scan.

Ground rules, which you must always follow:
- You have NO ability to run scans, execute commands, connect to any host, or take any action on \
the network. You are strictly advisory: you explain, prioritize, summarize, and draft text.
- Base every factual claim strictly on the SCAN DATA provided below. Never invent findings, \
hosts, ports, or details that are not present in it. If the data doesn't answer the question, say so.
- If asked to perform an action (e.g. "run this exploit," "scan this host," "crack this hash"), \
clearly state that you cannot do this yourself, and instead suggest the specific command a human \
analyst could run themselves to do it.
- Keep answers concise and professional, the way one analyst would brief another.

SCAN: "{scan_name}"

SCAN DATA (JSON, per target -- domain, module results, and findings):
{scan_data_json}
"""


def _call_llm(system_prompt, messages):
    """Calls Groq's free, OpenAI-compatible chat completions API.

    `messages` is a list of {"role": "user"|"assistant", "content": str},
    matching the same shape used previously for the Anthropic Messages API --
    Groq just wants the system prompt prepended as its own message instead
    of passed as a separate top-level field.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set on the server. Get a free key (no credit "
            "card required) at https://console.groq.com/keys, then "
            "export GROQ_API_KEY=... before starting the Flask app."
        )
    resp = requests.post(
        GROQ_API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": GROQ_MODEL,
            "max_tokens": 1024,
            "messages": [{"role": "system", "content": system_prompt}] + messages,
        },
        timeout=60,
    )
    if not resp.ok:
        # Surface Groq's actual error body instead of a generic status code.
        try:
            detail = resp.json().get("error", {}).get("message", resp.text)
        except Exception:
            detail = resp.text
        raise RuntimeError(f"Groq API error ({resp.status_code}): {detail}")
    data = resp.json()
    choices = data.get("choices", [])
    if not choices:
        return "(The assistant returned an empty response.)"
    content = choices[0].get("message", {}).get("content", "")
    return content.strip() or "(The assistant returned an empty response.)"


@api_bp.route("/scans/<int:scan_id>/chat", methods=["GET"])
@login_required
def get_scan_chat(scan_id):
    Scan.query.get_or_404(scan_id)  # 404 if the scan doesn't exist
    messages = (
        ChatMessage.query.filter_by(scan_id=scan_id)
        .order_by(ChatMessage.id.asc())
        .all()
    )
    return jsonify([m.to_dict() for m in messages])


@api_bp.route("/scans/<int:scan_id>/ask", methods=["POST"])
@login_required
def ask_scan_assistant(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    data = request.get_json(force=True) or {}
    user_text = (data.get("message") or "").strip()
    if not user_text:
        return jsonify({"error": "message is required"}), 400

    user_msg = ChatMessage(scan_id=scan.id, role="user", content=user_text)
    db.session.add(user_msg)
    db.session.commit()

    history = (
        ChatMessage.query.filter_by(scan_id=scan.id)
        .order_by(ChatMessage.id.asc())
        .all()[-CHAT_HISTORY_LIMIT:]
    )

    scan_data_json = json.dumps(scan.to_targets_data(), indent=2)
    if len(scan_data_json) > SCAN_DATA_CHAR_LIMIT:
        scan_data_json = scan_data_json[:SCAN_DATA_CHAR_LIMIT] + "\n... [truncated]"

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
        scan_name=scan.name,
        scan_data_json=scan_data_json,
    )
    api_messages = [{"role": m.role, "content": m.content} for m in history]

    try:
        reply_text = _call_llm(system_prompt, api_messages)
    except Exception as e:
        error_msg = ChatMessage(
            scan_id=scan.id, role="assistant",
            content=f"[Could not reach the AI assistant: {e}]",
        )
        db.session.add(error_msg)
        db.session.commit()
        return jsonify({"error": str(e), "message": error_msg.to_dict()}), 502

    assistant_msg = ChatMessage(scan_id=scan.id, role="assistant", content=reply_text)
    db.session.add(assistant_msg)
    db.session.commit()

    return jsonify({"message": assistant_msg.to_dict()})


# ---------------------------------------------------------------
# Scans
# ---------------------------------------------------------------
@api_bp.route("/scans", methods=["GET"])
@login_required
def list_scans():
    scans = Scan.query.order_by(Scan.started_at.desc()).all()
    return jsonify([s.to_summary_dict() for s in scans])


@api_bp.route("/scans", methods=["POST"])
@login_required
def create_scan():
    data = request.get_json(force=True) or {}

    name = (data.get("name") or "").strip()
    raw_targets = data.get("targets") or []
    ad_enabled = bool(data.get("ad_enabled"))
    domain = (data.get("domain") or "").strip()
    dc_ip = (data.get("dc_ip") or "").strip()
    username = data.get("username", "") or ""
    password = data.get("password", "") or ""

    targets = [t.strip() for t in raw_targets if t and t.strip()]
    if not targets:
        return jsonify({"error": "at least one target is required"}), 400
    if ad_enabled and not domain:
        return jsonify({"error": "domain is required when scanning an AD Domain Controller"}), 400

    if not name:
        name = f"Scan against {targets[0]}" + (f" (+{len(targets) - 1} more)" if len(targets) > 1 else "")

    target_specs = [
        {
            "ip": ip,
            "domain": domain if ad_enabled else "",
            "dc_ip": dc_ip or ip,
            "is_dc": ad_enabled,
            "username": username,
            "password": password,
        }
        for ip in targets
    ]

    scan = orchestrator.start_scan(name, target_specs, current_user.id)
    return jsonify({"message": "Scan started", "scan_id": scan.id}), 202


@api_bp.route("/scans/<int:scan_id>", methods=["GET"])
@login_required
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({
        "id": scan.id,
        "name": scan.name,
        "status": scan.status,
        "running": scan.status == "running",
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "duration_seconds": scan.duration_seconds,
        "log": scan.merged_log_lines(),
        "targets": {t.ip: t.to_dict() for t in scan.targets},
    })


@api_bp.route("/scans/<int:scan_id>/report", methods=["GET"])
@login_required
def scan_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    targets_data = scan.to_targets_data()
    if not targets_data:
        return jsonify({"error": "This scan has no target data"}), 400

    # Overrides from the "Generate Report" modal; each falls back to a
    # sensible default derived from the scan / logged-in user.
    engagement_name = request.args.get("name", "").strip() or scan.name
    client_name = request.args.get("client", "").strip() or None
    pentester_name = request.args.get("author", "").strip() or current_user.username

    report_dir = current_app.config["REPORT_DIR"]
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"ancscan_scan_{scan.id}.pdf")

    rep = Reporter(
        report_path,
        targets_data,
        engagement_name=engagement_name,
        pentester_name=pentester_name,
        client_name=client_name,
    )
    rep.build()

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in engagement_name)
    return send_file(report_path, as_attachment=True, download_name=f"{safe_name}_report.pdf")


# ---------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------
@api_bp.route("/notifications", methods=["GET"])
@login_required
def list_notifications():
    notes = (
        Notification.query
        .filter((Notification.user_id == current_user.id) | (Notification.user_id.is_(None)))
        .order_by(Notification.created_at.desc())
        .limit(50)
        .all()
    )
    return jsonify([n.to_dict() for n in notes])


@api_bp.route("/notifications/<int:note_id>/read", methods=["POST"])
@login_required
def mark_notification_read(note_id):
    note = Notification.query.get_or_404(note_id)
    note.read = True
    db.session.commit()
    return jsonify({"ok": True})


@api_bp.route("/notifications/read_all", methods=["POST"])
@login_required
def mark_all_notifications_read():
    notes = Notification.query.filter(
        (Notification.user_id == current_user.id) | (Notification.user_id.is_(None))
    ).filter_by(read=False).all()
    for n in notes:
        n.read = True
    db.session.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------
# Analytics (cross-scan, BI-style dashboard)
# ---------------------------------------------------------------
@api_bp.route("/analytics", methods=["GET"])
@login_required
def analytics():
    from models import ScanTarget, Finding
    from sqlalchemy import func

    scans = Scan.query.order_by(Scan.started_at.asc()).all()

    # ---- KPI cards ----
    total_scans = len(scans)
    total_hosts = ScanTarget.query.count()
    total_findings = Finding.query.count()
    finished_scans = [s for s in scans if s.finished_at]
    avg_duration = (
        sum(s.duration_seconds for s in finished_scans) / len(finished_scans)
        if finished_scans else 0
    )

    # ---- Severity trend across scans, chronological ----
    trend = []
    for s in scans:
        counts = s.severity_counts()
        trend.append({
            "scan_id": s.id,
            "scan_name": s.name,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "counts": counts,
        })

    # ---- Findings by category (all-time) ----
    category_rows = (
        db.session.query(Finding.category, func.count(Finding.id))
        .group_by(Finding.category)
        .all()
    )
    category_counts = {cat or "Uncategorized": cnt for cat, cnt in category_rows}

    # ---- Riskiest hosts: Critical+High findings per IP, across all scans ----
    host_rows = (
        db.session.query(ScanTarget.ip, Finding.severity, func.count(Finding.id))
        .join(Finding, Finding.scan_target_id == ScanTarget.id)
        .group_by(ScanTarget.ip, Finding.severity)
        .all()
    )
    host_severity = {}
    for ip, severity, cnt in host_rows:
        host_severity.setdefault(ip, {s: 0 for s in ["Critical", "High", "Medium", "Low", "Info"]})
        if severity in host_severity[ip]:
            host_severity[ip][severity] = cnt
    riskiest_hosts = sorted(
        [{"ip": ip, "counts": counts} for ip, counts in host_severity.items()],
        key=lambda h: (h["counts"]["Critical"], h["counts"]["High"]),
        reverse=True,
    )[:10]

    # ---- Recurring findings: same title seen across multiple scans/hosts ----
    title_rows = (
        db.session.query(Finding.title, Finding.severity, func.count(Finding.id))
        .group_by(Finding.title, Finding.severity)
        .having(func.count(Finding.id) > 1)
        .order_by(func.count(Finding.id).desc())
        .limit(10)
        .all()
    )
    recurring = [{"title": t, "severity": sev, "count": cnt} for t, sev, cnt in title_rows]

    return jsonify({
        "kpis": {
            "total_scans": total_scans,
            "total_hosts": total_hosts,
            "total_findings": total_findings,
            "avg_duration_seconds": avg_duration,
        },
        "trend": trend,
        "category_counts": category_counts,
        "riskiest_hosts": riskiest_hosts,
        "recurring_findings": recurring,
    })


# ---------------------------------------------------------------
# Vulnerabilities library (every finding, across every scan)
# ---------------------------------------------------------------
@api_bp.route("/vulnerabilities", methods=["GET"])
@login_required
def list_all_vulnerabilities():
    from models import ScanTarget, Finding

    rows = (
        db.session.query(Finding, ScanTarget, Scan)
        .join(ScanTarget, Finding.scan_target_id == ScanTarget.id)
        .join(Scan, ScanTarget.scan_id == Scan.id)
        .order_by(Scan.started_at.desc(), Finding.id.desc())
        .all()
    )

    results = []
    for f, t, s in rows:
        results.append({
            "id": f.id,
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "detail": f.detail,
            "recommendation": f.recommendation,
            "host": t.ip,
            "scan_id": s.id,
            "scan_name": s.name,
            "found_at": s.started_at.isoformat() if s.started_at else None,
        })

    return jsonify(results)


# ---------------------------------------------------------------
# Team management (admin-only)
# ---------------------------------------------------------------
def _require_admin():
    if not current_user.is_admin:
        abort(403)


@api_bp.route("/team", methods=["GET"])
@login_required
def list_team():
    _require_admin()
    users = User.query.order_by(User.created_at.asc()).all()
    return jsonify([u.to_dict() for u in users])


@api_bp.route("/team", methods=["POST"])
@login_required
def add_team_member():
    _require_admin()
    data = request.get_json(force=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    is_admin = bool(data.get("is_admin"))

    if not username or not email:
        return jsonify({"error": "username and email are required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "That username is already taken"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "That email is already registered"}), 400

    # Set an unguessable temporary password immediately, then invite the
    # new user to set their own via the same reset-token flow used for
    # forgot-password -- they never see (and we never transmit) this value.
    temp_password = secrets.token_urlsafe(12)
    user = User(username=username, email=email, is_admin=is_admin)
    user.set_password(temp_password)
    db.session.add(user)
    db.session.commit()

    token = user.generate_reset_token()
    db.session.commit()
    setup_url = url_for("auth.reset_password", token=token, _external=True)

    sent = send_email(
        email,
        "You've been added to ANCScan",
        f"An ANCScan account was created for you by {current_user.username}.\n\n"
        f"Set your password here (expires in 1 hour):\n{setup_url}\n\n"
        f"Username: {username}",
    )

    response = {"user": user.to_dict()}
    if not sent:
        # No SMTP configured -- return the setup link directly so the admin
        # can hand it to the new pentester manually (dev-mode fallback).
        response["dev_setup_link"] = setup_url

    return jsonify(response), 201


@api_bp.route("/team/<int:user_id>", methods=["DELETE"])
@login_required
def remove_team_member(user_id):
    _require_admin()
    if user_id == current_user.id:
        return jsonify({"error": "You cannot remove your own account"}), 400

    user = User.query.get_or_404(user_id)
    if user.is_admin and User.query.filter_by(is_admin=True).count() <= 1:
        return jsonify({"error": "Cannot remove the last remaining admin"}), 400

    db.session.delete(user)
    db.session.commit()
    return jsonify({"ok": True})
