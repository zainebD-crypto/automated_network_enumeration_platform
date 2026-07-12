# ANCScan — Automated Network Enumeration Platform

## 1. Short Intro

ANCScan automates the reconnaissance and enumeration phase of an internal
penetration test — the repetitive, mechanical part that normally takes an
analyst hours of manually running `nmap`, `enum4linux-ng`, and Impacket
scripts by hand. Point it at one or more targets, optionally flag a target
as an Active Directory Domain Controller, and it runs host discovery, port
and service enumeration, SMB enumeration, AD enumeration (Kerberoasting /
AS-REP roasting detection), and CVE-based vulnerability mapping — then
generates a client-ready PDF report automatically. Everything is scoped to
passive/semi-passive enumeration only: ANCScan never launches exploits,
brute-forces credentials, or takes any action beyond information gathering.

It started as a set of standalone CLI scripts during an internship at the
National Agency of Cybersecurity (ANC), Tunisia, and grew into a full
multi-user web platform with scan history, an AI advisory assistant, and
team management.
![ANCScan Dashboard](Screenshot%20From%202026-07-11%2022-53-30.png) 
---

## 2. Technologies

**Backend**
- Python 3
- Flask (app factory pattern, organized as blueprints)
- Flask-SQLAlchemy + SQLite (persistent scan history, findings, users)
- Flask-Login (authentication/session management)

**Enumeration modules**
- `python-nmap` — host discovery, port/service/OS fingerprinting
- `Impacket` + `ldap3` — SMB enumeration, Active Directory enumeration
- Nmap's vulnerability scripting engine — CVE-based vulnerability mapping

**Reporting & AI**
- ReportLab — PDF report generation
- Groq API (Llama 3.3 70B) — the "Ask ANCScan" advisory assistant, grounded
  strictly in a scan's own persisted data, with no tool-execution access

**Frontend**
- Server-rendered Jinja2 templates
- Vanilla HTML/CSS/JS — no frontend framework or build step, so the project
  runs anywhere Python does with zero extra tooling
- Pure SVG/CSS charts (donuts, stacked bars, trend charts) — no charting
  library dependency, so the dashboard works even offline

**Infrastructure**
- Bounded `ThreadPoolExecutor` for concurrent multi-target scanning
- nginx (optional) as a reverse proxy for a clean local hostname

---

## 3. Features — What Users Can Do

- **Log in** with an individual account (no open self-registration — new
  pentester accounts are added by an admin from the Team page)
- **Launch a scan** against one or more targets at once, with an explicit
  toggle for "one of these targets is a Domain Controller" to enable AD
  enumeration
- **Watch a scan run live** — per-host module status, a live execution
  console merging every target's log output, and a ticking scan duration
- **Browse scan history** — every scan ever launched is persisted and
  stays accessible after a restart
- **Browse a cross-scan Vulnerabilities library** — every finding ever
  discovered, filterable by severity, category, and free-text search
- **View cross-scan Analytics** — KPI cards, a severity trend chart over
  time, findings-by-category breakdown, riskiest hosts ranking, and
  recurring-issue detection
- **Ask the AI assistant** questions about a specific scan's findings —
  prioritization, plain-language explanations, draft remediation wording —
  grounded strictly in that scan's real data
- **Export a PDF report** with a custom report name, client name, and
  author, generated on demand from the scan's persisted results
- **Manage the team** (admin only) — add pentester accounts, revoke access
- **Reset a forgotten password** via a self-service flow

---

## 4. Keyboard Shortcuts

Currently minimal — being honest here rather than overstating it:

| Shortcut | Where | Action |
|---|---|---|
| `Enter` | Ask ANCScan chat input | Send message |
| `Enter` | Any form (browser default) | Submit the form |

There are no other custom keybindings implemented yet (no shortcut to
launch a new scan, jump between tabs, etc.). This is listed explicitly in
Section 7 as a good first contribution for anyone joining the project.

---

## 5. The Process — How This Was Built

Development followed the actual dependency order of the system, not a
big-upfront design:

1. **Standalone learning scripts** — a ping sweep, a port scan, and a
   service-version scan written directly against the `python-nmap` API in
   isolation, to understand its object model before building anything
   reusable on top of it.
2. **`recon.py`** — wrapped that into a proper class: a lightweight host
   discovery method (`-sn`) separated from the more expensive detailed
   scan (`-sV -sC -O`), each returning a normalized dictionary.
3. **`enum_smb.py` / `enum_ad.py`** — SMB null-session/share enumeration
   and Active Directory enumeration (Kerberoastable / AS-REP roastable
   account detection), each validated against a lab domain with
   *deliberately* introduced, known misconfigurations, so expected output
   was known in advance rather than guessed at.
4. **`vuln_mapper.py`** — started as simple port-number heuristics; this
   turned out to misfire (flagging Linux hosts as "possible WinRM" purely
   from an open HTTP port), which motivated switching to nmap's
   vulnerability scripting engine for real CVE identification instead of
   an inferred guess.
5. **`reporter.py`** — a ReportLab-based PDF generator, iterated through a
   real rendering bug (unwrapped table cells overflowing into neighboring
   columns) that only became visible once actual PDFs were inspected.
6. **A single-file Flask dashboard** — the first web UI, one global
   in-memory state dict, one target at a time. This deliberately simple
   version exposed its own limitations fast: launching a second scan
   silently overwrote the first one's results.
7. **A full platform rewrite** — SQLite + SQLAlchemy for real persistence,
   a bounded thread pool for concurrent multi-target scanning, Flask
   blueprints separating auth/scans/api, and a rebuilt frontend (sidebar
   navigation, scan history, per-scan detail pages).
8. **Layered on top**: an Analytics page, a cross-scan Vulnerabilities
   library, the AI advisory chat (deliberately scoped to read-only —
   grounded in a scan's data with zero tool-execution access), and
   admin-gated team management with a proper password-reset flow.

---

## 6. What I Learned

- **API exploration before abstraction.** Writing raw, throwaway scripts
  against `python-nmap` first — before wrapping it in a class — made the
  eventual `Recon` class's design decisions obvious rather than guessed.
- **Validate against a known ground truth.** Deliberately building a lab
  domain with specific, documented misconfigurations (rather than testing
  against an arbitrary network) meant every module's output could be
  checked against an exact expected answer, not just "does this look
  plausible."
- **A rendering bug is invisible in code review.** The ReportLab table
  cell-wrapping issue only showed up once the actual generated PDF was
  opened and inspected — a reminder that a report generator's real
  correctness criterion is the rendered output, not the code.
- **In-memory state doesn't survive real use.** The first Flask dashboard
  worked fine for a demo and broke immediately under real usage (launch a
  second scan, lose the first). This is what motivated the database-backed
  rewrite rather than patching around the symptom.
- **Concurrency needs a ceiling.** Naively threading "one thread per
  target" scales fine at 2 hosts and badly at 50 — bounding the thread
  pool was a deliberate scalability decision, not an afterthought.
- **An AI feature needs an architectural boundary, not just a prompt
  instruction.** The advisory assistant's "it can't act" guarantee comes
  from the API call having no `tools` parameter at all, not from asking
  the model nicely not to. That distinction matters a lot for a security
  tool specifically.
- **Git/GitHub auth is its own skill.** Password auth for git was removed
  by GitHub years ago; getting a token with the right scope (classic vs.
  fine-grained), or SSH keys set up correctly, took real, patient
  debugging — a good reminder that "just push it" hides a surprising
  amount of infrastructure underneath.

---

## 7. How This Project Can Be Improved

Roughly in priority order:

- **Retesting / diff between scans** — compare two scans of the same
  target over time and report which findings were resolved, which
  persist, and which are new. High value, not yet built.
- **Real SMTP by default** — password reset and team invites currently
  fall back to showing the link directly in the UI when no mail server is
  configured; wiring up a default transactional email provider would make
  onboarding smoother for real teams.
- **Broader CVE sourcing** — layer an NVD API lookup on top of nmap's
  vulnerability scripts for additional coverage and richer CVSS data.
- **Role-based access beyond admin/analyst** — finer-grained permissions
  (e.g., read-only viewer role) for larger teams.
- **Real-time updates over polling** — the dashboard currently polls on
  an interval; WebSockets would make live scan progress feel more
  immediate and reduce request overhead.
- **Keyboard shortcuts** — see Section 4; a good, contained first issue
  for a new contributor.
- **Automated tests** — current validation is manual, against the lab
  environment; a proper test suite (especially around the orchestrator's
  concurrency behavior) would catch regressions much earlier.
- **Multi-format export** — the report modal already has a Format field
  wired up in the UI but locked to PDF; HTML/CSV export would be a
  natural extension using the same underlying data.

---

## 8. Steps of Running the Project

### Prerequisites
- Python 3.11+
- `nmap` installed (`sudo apt install nmap` on Kali/Debian)
- A free [Groq API key](https://console.groq.com/keys) (no credit card) for
  the AI assistant — optional, the rest of the platform works without it

### Setup

```bash
git clone https://github.com/<your-username>/automated_network_enumeration_platform.git
cd automated_network_enumeration_platform

python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

Set required environment variables:

```bash
export GROQ_API_KEY="gsk_your_key_here"
```

Run it:

```bash
cd Platform
python app.py
```

First run auto-creates `Platform/ancscan.db` and prints a default admin
login to the console (`admin` / `changeme`) — **change this immediately**
before exposing the app beyond `localhost`.

Open `http://127.0.0.1:5000`.

### Upgrading an existing installation

If you have an `ancscan.db` predating the Team/auth features, migrate
before starting the app so existing scan history isn't lost:

```bash
cd Platform
python3 migrate_add_user_fields.py
python app.py
```

See `.env.example` for optional configuration (custom Groq model, SMTP for
real email delivery, session secret key).

---

## 9. Demo Video

*(Placeholder — record a short screen-capture walking through: logging
in, launching a multi-target scan, watching live progress, opening the
Vulnerabilities library, asking the AI assistant a question, and
exporting a PDF report. Tools like OBS Studio or `asciinema` work well for
this on Kali. Once recorded, link it here or embed it if hosting on
GitHub — e.g. upload to a video host and paste the link below.)*

[Demo video link — add here]

---

## License / Usage

Internal project developed during an internship at the National Agency of
Cybersecurity (ANC), Tunisia. Intended for authorized internal penetration
testing use only.
