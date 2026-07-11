"""
models.py — SQLAlchemy models for the ANCScan platform.

Everything the platform persists lives here:
  User          - pentesters who log in
  Scan          - one "run" of the platform; may contain many targets,
                  survives Flask restarts, and is the unit shown in the
                  "My Scans" history list.
  ScanTarget    - one host within a scan (an IP, optionally AD-related)
  ModuleResult  - the raw result of one enumeration module against one target
  Finding       - one normalized security finding tied to a target
  ScanLogEntry  - one line of the execution console for a scan
  Notification  - one bell-icon notification for a user

Design note on credentials: AD username/password supplied for a scan are
NEVER written to this database. They are held only in an in-memory dict in
orchestrator.py for the lifetime of that scan's background threads, then
discarded. This avoids storing domain credentials in cleartext on disk.
"""
import json
import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
MODULE_ORDER = ["recon", "smb", "ad", "vuln"]


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    reset_token = db.Column(db.String(64), nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self):
        import secrets
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expires = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        return self.reset_token

    def verify_reset_token(self, token):
        return bool(
            self.reset_token and self.reset_token == token
            and self.reset_token_expires
            and self.reset_token_expires > datetime.datetime.utcnow()
        )

    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expires = None

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_by = db.relationship("User")

    status = db.Column(db.String(20), default="running")  # running|completed|failed
    started_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    finished_at = db.Column(db.DateTime, nullable=True)

    targets = db.relationship(
        "ScanTarget", backref="scan", cascade="all, delete-orphan", order_by="ScanTarget.id"
    )
    logs = db.relationship(
        "ScanLogEntry", backref="scan", cascade="all, delete-orphan", order_by="ScanLogEntry.id"
    )

    @property
    def duration_seconds(self):
        end = self.finished_at or datetime.datetime.utcnow()
        return max(0, (end - self.started_at).total_seconds())

    @property
    def host_count(self):
        return len(self.targets)

    def severity_counts(self):
        counts = {s: 0 for s in SEV_ORDER}
        for t in self.targets:
            for f in t.findings:
                if f.severity in counts:
                    counts[f.severity] += 1
        return counts

    def to_summary_dict(self):
        counts = self.severity_counts()
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "host_count": self.host_count,
            "severity_counts": counts,
            "total_findings": sum(counts.values()),
            "created_by": self.created_by.username if self.created_by else None,
        }

    def to_targets_data(self):
        """Shape expected by modules/reporter.py's Reporter class."""
        return {
            t.ip: {
                "domain": t.domain,
                "modules": t.modules_dict(),
                "security_findings": [f.to_dict() for f in t.findings],
            }
            for t in self.targets
        }

    def merged_log_lines(self):
        return [entry.to_line() for entry in self.logs]


class ScanTarget(db.Model):
    __tablename__ = "scan_targets"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)

    ip = db.Column(db.String(64), nullable=False)
    domain = db.Column(db.String(200), nullable=True)
    dc_ip = db.Column(db.String(64), nullable=True)
    is_dc = db.Column(db.Boolean, default=False)

    status = db.Column(db.String(20), default="queued")  # queued|running|completed|failed
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    module_results = db.relationship(
        "ModuleResult", backref="target", cascade="all, delete-orphan"
    )
    findings = db.relationship(
        "Finding", backref="target", cascade="all, delete-orphan"
    )

    @property
    def duration_seconds(self):
        if not self.started_at:
            return 0
        end = self.finished_at or datetime.datetime.utcnow()
        return max(0, (end - self.started_at).total_seconds())

    def module(self, name):
        for m in self.module_results:
            if m.module_name == name:
                return m
        return None

    def modules_dict(self):
        out = {}
        for name in MODULE_ORDER:
            m = self.module(name)
            out[name] = {
                "status": m.status if m else "queued",
                "result": m.result() if m else None,
                "error": m.error if m else None,
            }
        return out

    def to_dict(self):
        return {
            "ip": self.ip,
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "is_dc": self.is_dc,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "modules": self.modules_dict(),
            "security_findings": [f.to_dict() for f in self.findings],
        }


class ModuleResult(db.Model):
    __tablename__ = "module_results"

    id = db.Column(db.Integer, primary_key=True)
    scan_target_id = db.Column(db.Integer, db.ForeignKey("scan_targets.id"), nullable=False)
    module_name = db.Column(db.String(20), nullable=False)  # recon|smb|ad|vuln
    status = db.Column(db.String(20), default="queued")  # queued|running|completed|failed|skipped
    result_json = db.Column(db.Text, nullable=True)
    error = db.Column(db.Text, nullable=True)

    def result(self):
        if not self.result_json:
            return None
        return json.loads(self.result_json)

    def set_result(self, data):
        self.result_json = json.dumps(data) if data is not None else None


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_target_id = db.Column(db.Integer, db.ForeignKey("scan_targets.id"), nullable=False)

    severity = db.Column(db.String(20))
    category = db.Column(db.String(50))
    title = db.Column(db.String(200))
    detail = db.Column(db.Text)
    recommendation = db.Column(db.Text)

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


class ScanLogEntry(db.Model):
    __tablename__ = "scan_log_entries"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    target_ip = db.Column(db.String(64), nullable=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_line(self):
        ts = self.created_at.strftime("%H:%M:%S")
        prefix = f"[{ts}] [{self.target_ip}] " if self.target_ip else f"[{ts}] "
        return prefix + self.message


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)  # null = broadcast
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)
    level = db.Column(db.String(20), default="info")  # info|success|warning|error
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "level": self.level,
            "message": self.message,
            "created_at": self.created_at.isoformat(),
            "read": self.read,
        }


class ChatMessage(db.Model):
    """One message in the per-scan AI advisory chat. The assistant is strictly
    read-only/advisory: it is grounded in this scan's persisted data and has
    no ability to trigger scans or touch the network — see api.py."""
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # "user" | "assistant"
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "role": self.role,
            "content": self.content,
            "created_at": self.created_at.isoformat(),
        }
