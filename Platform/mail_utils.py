"""
mail_utils.py — minimal, optional SMTP email sending for ANCScan.

If SMTP isn't configured via environment variables, send_email() simply
returns False rather than raising. Callers (auth.py, api.py's team
endpoints) fall back to displaying the action link directly in a flash
message / API response when this happens -- clearly labeled as a dev-mode
fallback. This keeps password reset and team invites testable out of the
box on a lab machine with no mail relay, without silently failing.

To enable real email delivery, set:
  ANCSCAN_SMTP_HOST, ANCSCAN_SMTP_PORT, ANCSCAN_SMTP_USER,
  ANCSCAN_SMTP_PASSWORD, ANCSCAN_SMTP_FROM (optional, defaults to SMTP_USER)

For example, with a Gmail app password:
  export ANCSCAN_SMTP_HOST=smtp.gmail.com
  export ANCSCAN_SMTP_PORT=587
  export ANCSCAN_SMTP_USER=youraddress@gmail.com
  export ANCSCAN_SMTP_PASSWORD=your-16-char-app-password
"""
import os
import smtplib
from email.mime.text import MIMEText


def is_configured():
    return bool(
        os.environ.get("ANCSCAN_SMTP_HOST")
        and os.environ.get("ANCSCAN_SMTP_USER")
        and os.environ.get("ANCSCAN_SMTP_PASSWORD")
    )


def send_email(to_addr, subject, body):
    """Returns True if the email was actually sent, False if SMTP isn't
    configured (never raises for the "not configured" case -- only for
    genuine send failures once SMTP *is* configured)."""
    if not is_configured():
        return False

    host = os.environ["ANCSCAN_SMTP_HOST"]
    port = int(os.environ.get("ANCSCAN_SMTP_PORT", "587"))
    user = os.environ["ANCSCAN_SMTP_USER"]
    password = os.environ["ANCSCAN_SMTP_PASSWORD"]
    from_addr = os.environ.get("ANCSCAN_SMTP_FROM", user)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr

    with smtplib.SMTP(host, port, timeout=15) as server:
        server.starttls()
        server.login(user, password)
        server.sendmail(from_addr, [to_addr], msg.as_string())
    return True
