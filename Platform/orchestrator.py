"""
orchestrator.py — DB-backed pipeline orchestrator for the ANCScan platform.

Every scan is a persistent `Scan` row containing one or more `ScanTarget`
rows. Targets run concurrently via a BOUNDED thread pool (not one thread
per target with no ceiling), so scanning a large host count degrades
gracefully instead of spawning hundreds of nmap subprocesses at once.

Does not reimplement any module logic — imports and calls the classes
already built in modules/.

SECURITY NOTE: AD credentials supplied for a scan are held ONLY in the
in-memory `_pending_credentials` dict below, for the lifetime of that
target's background thread, then discarded. They are never written to
the database.
"""
import datetime
from concurrent.futures import ThreadPoolExecutor

from extensions import db
from models import Scan, ScanTarget, ModuleResult, Finding, ScanLogEntry, Notification

from modules.recon import Recon
from modules.enum_smb import SMBEnum
from modules.enum_ad import ADEnum
from modules.vuln_mapper import VulnMapper

# Ceiling on how many targets run at once, across ALL scans. Raise this if
# your box can handle more concurrent nmap/smb/ldap connections; keep it
# bounded so "scan 300 hosts" doesn't fork 300 threads simultaneously.
MAX_CONCURRENT_TARGETS = 10
_executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TARGETS)

# target_id -> (username, password), consumed once by that target's thread
# and popped immediately. Never persisted to disk.
_pending_credentials = {}

_app = None  # set via init_app() so background threads can push an app context


def init_app(flask_app):
    global _app
    _app = flask_app


def _log(scan_id, target_ip, message):
    entry = ScanLogEntry(scan_id=scan_id, target_ip=target_ip, message=message)
    db.session.add(entry)
    db.session.commit()


def _get_or_create_module(target, name):
    m = target.module(name)
    if not m:
        m = ModuleResult(scan_target_id=target.id, module_name=name, status="queued")
        db.session.add(m)
        db.session.commit()
    return m


def _set_module(target, name, status, result=None, error=None):
    m = _get_or_create_module(target, name)
    m.status = status
    if result is not None:
        m.set_result(result)
    if error is not None:
        m.error = error
    db.session.commit()


def _build_findings(recon_result, smb_result, ad_result, vuln_result):
    findings = []

    for host, host_findings in (vuln_result or {}).items():
        for f in host_findings:
            findings.append({
                "category": "Network",
                "title": f.get("title"),
                "severity": f.get("severity"),
                "detail": f"{host} — port {f.get('port')}/{f.get('service')}",
                "recommendation": f.get("note"),
            })

    if ad_result:
        for user in ad_result.get("kerberoastable", []):
            findings.append({
                "category": "Active Directory",
                "title": "Kerberoastable account",
                "severity": "High",
                "detail": f"Account '{user}' has a Service Principal Name set",
                "recommendation": "Use a strong, randomly generated password (25+ chars) or a Group Managed Service Account (gMSA).",
            })
        for user in ad_result.get("asrep_roastable", []):
            findings.append({
                "category": "Active Directory",
                "title": "AS-REP roastable account",
                "severity": "High",
                "detail": f"Account '{user}' does not require Kerberos pre-authentication",
                "recommendation": "Re-enable Kerberos pre-authentication unless explicitly required.",
            })
        if ad_result.get("domain_admins"):
            findings.append({
                "category": "Active Directory",
                "title": "Domain Admins membership disclosed",
                "severity": "Info",
                "detail": f"{len(ad_result['domain_admins'])} member(s) enumerated via LDAP",
                "recommendation": "Minimize standing Domain Admin membership; use PAM/JIT elevation where possible.",
            })

    if smb_result:
        if smb_result.get("anonymous_access"):
            findings.append({
                "category": "SMB",
                "title": "Anonymous / null-session SMB access permitted",
                "severity": "Critical",
                "detail": f"Target {smb_result.get('target')} accepted an unauthenticated SMB session",
                "recommendation": "Disable anonymous logon rights and restrict null-session access via Local Security Policy.",
            })
        for share, contents in (smb_result.get("shares") or {}).items():
            if contents and not (len(contents) == 1 and "error" in contents[0]):
                findings.append({
                    "category": "SMB",
                    "title": f"Accessible share: {share}",
                    "severity": "High" if smb_result.get("anonymous_access") else "Medium",
                    "detail": f"{len(contents)} item(s) visible",
                    "recommendation": "Review share and NTFS permissions; remove Everyone/anonymous access unless required.",
                })

    order = {s: i for i, s in enumerate(["Critical", "High", "Medium", "Low", "Info"])}
    findings.sort(key=lambda f: order.get(f["severity"], 5))
    return findings


def _finalize_scan_if_done(scan_id):
    scan = Scan.query.get(scan_id)
    if not scan:
        return
    statuses = [t.status for t in scan.targets]
    if statuses and all(s in ("completed", "failed") for s in statuses):
        scan.status = "failed" if any(s == "failed" for s in statuses) else "completed"
        scan.finished_at = datetime.datetime.utcnow()
        db.session.commit()

        counts = scan.severity_counts()
        total = sum(counts.values())
        note = Notification(
            user_id=scan.created_by_id,
            scan_id=scan.id,
            level="warning" if (counts["Critical"] or counts["High"]) else "success",
            message=(
                f"Scan '{scan.name}' finished — {scan.host_count} host(s), {total} finding(s) "
                f"({counts['Critical']} Critical, {counts['High']} High)."
            ),
        )
        db.session.add(note)
        db.session.commit()


def _run_one_target(scan_id, target_id):
    """Runs the full module pipeline for ONE target. Executed inside the
    bounded thread pool; pushes its own Flask app context for DB access."""
    with _app.app_context():
        target = ScanTarget.query.get(target_id)
        if not target:
            return

        ad_username, ad_password = _pending_credentials.pop(target_id, ("", ""))

        target.status = "running"
        target.started_at = datetime.datetime.utcnow()
        db.session.commit()

        _log(scan_id, target.ip, f"Attack started against {target.ip} (domain: {target.domain or 'N/A'})")

        # --- Recon ---
        recon_result = None
        _set_module(target, "recon", "running")
        _log(scan_id, target.ip, "Running recon module (port/service/OS scan)...")
        try:
            recon_result = Recon(target.ip, deep=False).run()
            _set_module(target, "recon", "completed", result=recon_result)
            _log(scan_id, target.ip,
                 f"Recon completed: {len(recon_result.get(target.ip, {}).get('ports', {}))} open ports found")
        except Exception as e:
            _set_module(target, "recon", "failed", error=str(e))
            _log(scan_id, target.ip, f"Recon FAILED: {e}")

        # --- SMB ---
        smb_result = None
        _set_module(target, "smb", "running")
        _log(scan_id, target.ip, "Running SMB enumeration...")
        try:
            smb_result = SMBEnum(target.ip).run()
            _set_module(target, "smb", "completed", result=smb_result)
            _log(scan_id, target.ip,
                 f"SMB enumeration completed (anonymous access: {smb_result.get('anonymous_access')})")
        except Exception as e:
            _set_module(target, "smb", "failed", error=str(e))
            _log(scan_id, target.ip, f"SMB enumeration FAILED: {e}")

        # --- AD (only if a domain was supplied for this target) ---
        ad_result = None
        if target.domain:
            _set_module(target, "ad", "running")
            _log(scan_id, target.ip, "Running Active Directory enumeration...")
            try:
                ad_result = ADEnum(
                    target.dc_ip or target.ip, target.domain, ad_username, ad_password
                ).run()
                _set_module(target, "ad", "completed", result=ad_result)
                kcount = len(ad_result.get("kerberoastable", []))
                acount = len(ad_result.get("asrep_roastable", []))
                _log(scan_id, target.ip,
                     f"AD enumeration completed: {kcount} Kerberoastable, {acount} AS-REP roastable account(s)")
            except Exception as e:
                _set_module(target, "ad", "failed", error=str(e))
                _log(scan_id, target.ip, f"AD enumeration FAILED: {e}")
        else:
            _set_module(target, "ad", "skipped")
            _log(scan_id, target.ip, "AD enumeration SKIPPED: no domain supplied for this target")

        # --- Vulnerability mapping ---
        vuln_result = None
        _set_module(target, "vuln", "running")
        _log(scan_id, target.ip, "Running vulnerability mapping on recon output...")
        try:
            if recon_result:
                vuln_result = VulnMapper(recon_result).run()
                _set_module(target, "vuln", "completed", result=vuln_result)
                total = sum(len(v) for v in vuln_result.values())
                _log(scan_id, target.ip, f"Vulnerability mapping completed: {total} issue(s) mapped")
            else:
                _set_module(target, "vuln", "failed", error="No recon data available")
                _log(scan_id, target.ip, "Vulnerability mapping SKIPPED: no recon data")
        except Exception as e:
            _set_module(target, "vuln", "failed", error=str(e))
            _log(scan_id, target.ip, f"Vulnerability mapping FAILED: {e}")

        findings = _build_findings(recon_result, smb_result, ad_result, vuln_result)
        for f in findings:
            db.session.add(Finding(scan_target_id=target.id, **f))

        target_failed = any(
            target.module(name) and target.module(name).status == "failed"
            for name in ("recon", "smb", "vuln")
        )
        target.status = "failed" if target_failed else "completed"
        target.finished_at = datetime.datetime.utcnow()
        db.session.commit()

        _log(scan_id, target.ip, f"Pipeline complete: {len(findings)} total findings")
        _finalize_scan_if_done(scan_id)


def start_scan(name, target_specs, created_by_id):
    """Create a new Scan with one or more targets and kick off bounded
    concurrent background execution.

    target_specs: list of dicts, e.g.
      [{"ip": "10.0.0.5", "domain": "corp.local", "dc_ip": "10.0.0.5",
        "is_dc": True, "username": "", "password": ""}, ...]

    Returns the new Scan row (already committed, with an id).
    """
    scan = Scan(name=name, created_by_id=created_by_id, status="running")
    db.session.add(scan)
    db.session.flush()  # assigns scan.id before we attach targets

    target_rows = []
    for spec in target_specs:
        t = ScanTarget(
            scan_id=scan.id,
            ip=spec["ip"].strip(),
            domain=(spec.get("domain") or "").strip() or None,
            dc_ip=(spec.get("dc_ip") or "").strip() or None,
            is_dc=bool(spec.get("is_dc")),
            status="queued",
        )
        db.session.add(t)
        db.session.flush()  # assigns t.id

        username = spec.get("username", "")
        password = spec.get("password", "")
        if username or password:
            _pending_credentials[t.id] = (username, password)

        target_rows.append(t)

    db.session.commit()

    for t in target_rows:
        _executor.submit(_run_one_target, scan.id, t.id)

    return scan
