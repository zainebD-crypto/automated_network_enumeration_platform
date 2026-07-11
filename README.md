# ANCScan — Automated Network Enumeration Platform

ANCScan automates the reconnaissance and enumeration phase of an internal
penetration test: host/service discovery, SMB enumeration, Active Directory
enumeration (Kerberoasting / AS-REP roasting detection), CVE-based
vulnerability mapping, and automatic PDF report generation — all through a
web dashboard with scan history, multi-target concurrent scanning, and an
AI advisory assistant grounded in each scan's actual findings.

> **Scope note:** ANCScan is strictly a passive/semi-passive enumeration
> tool. It does not launch exploits, brute-force credentials, or take any
> action beyond information gathering. Only use it against networks you are
> explicitly authorized to test.

---

## Project Structure

```
ANCScan/
├── modules/            # Enumeration modules (recon, SMB, AD, vuln mapping, reporter)
├── Platform/            # Flask web application
│   ├── app.py            # App factory / entry point
│   ├── models.py         # SQLAlchemy models
│   ├── orchestrator.py   # Scan execution (bounded thread pool)
│   ├── auth.py            # Login / password reset
│   ├── team.py            # Admin-only team management
│   ├── api.py              # JSON API (scans, findings, AI chat, team)
│   ├── mail_utils.py        # Optional SMTP for password reset / invites
│   ├── templates/
│   └── static/
├── output/              # Generated PDF reports (not tracked in git)
├── data/                 # Runtime data / CVE cache (not tracked in git)
├── requirements.txt
└── .env.example
```

---

## Prerequisites

- Python 3.11+
- `nmap` installed on the system (`sudo apt install nmap` on Kali/Debian)
- A free [Groq API key](https://console.groq.com/keys) for the AI advisory
  assistant (optional — the rest of the platform works without it)

---

## Setup (reproduction steps)

Clone the repo, then create and activate a virtual environment — **the venv
itself is not tracked in git**, you recreate it locally:

```bash
git clone https://github.com/<your-username>/ANCScan.git
cd ANCScan

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

Set your environment variables (copy `.env.example` as a reference — either
export these directly, or use a local `.env` file that stays untracked):

```bash
export GROQ_API_KEY="gsk_your_key_here"
```

Run the app for the first time:

```bash
cd Platform
python app.py
```

On first run, this automatically creates `Platform/ancscan.db` (SQLite) and
seeds a default admin account — the credentials are printed to the console:

```
username: admin
password: changeme
```

**Change this password immediately** (or set up a real account via the Team
page and remove/rotate the default one) before exposing the app beyond
`localhost`.

Open `http://127.0.0.1:5000` and log in.

---

## Upgrading an existing installation

If you already have an `ancscan.db` from an earlier version of ANCScan
(before the Team/authentication features were added), run the one-off
migration **before** starting the app, so your existing scan history isn't
lost:

```bash
cd Platform
python3 migrate_add_user_fields.py
python app.py
```

---

## Optional: real email delivery

By default, password reset and team-invite links are shown directly in the
UI (no email server required — fine for local/lab use). To enable real
email delivery, set:

```bash
export ANCSCAN_SMTP_HOST=smtp.example.com
export ANCSCAN_SMTP_PORT=587
export ANCSCAN_SMTP_USER=you@example.com
export ANCSCAN_SMTP_PASSWORD=your-app-password
```

See `.env.example` for the full list of optional configuration variables.

---

## Running behind a domain / reverse proxy

For a friendlier local hostname than `127.0.0.1:5000`, see the nginx +
`/etc/hosts` setup documented in the project wiki / internship report.

---

## License / Usage

Internal project developed during an internship at the National Agency of
Cybersecurity (ANC), Tunisia. Intended for authorized internal penetration
testing use only.
