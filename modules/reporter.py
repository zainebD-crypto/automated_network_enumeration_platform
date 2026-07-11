"""
reporter.py — PDF report generation module for ANCScan.

Builds a structured, client-ready penetration testing report (cover,
executive summary, scope, methodology, findings table, detailed findings,
attack path, remediation plan, appendix) from recon, SMB enum, AD enum,
and vulnerability mapping results, using ReportLab.

All content is derived strictly from the scan data passed in — nothing is
invented. If a section has no supporting data, it is rendered with a
plain "no data" note instead of being skipped silently.
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import datetime

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

SEV_COLOR = {
    "Critical": colors.HexColor("#d0374e"),
    "High": colors.HexColor("#e8813d"),
    "Medium": colors.HexColor("#f1c22e"),
    "Low": colors.HexColor("#4b9b5f"),
    "Info": colors.HexColor("#2f6fb3"),
}

RISK_RATING_BY_WORST_SEVERITY = {
    "Critical": "Extreme",
    "High": "High",
    "Medium": "Medium-Elevated",
    "Low": "Low",
    "Info": "Very Low",
}

NAVY = colors.HexColor("#003366")


class Reporter:
    """
    Expects `targets_data` shaped as:

    {
      "<ip>": {
        "domain": "ancs.local",
        "modules": {
          "recon": {"status": "completed", "result": {"<ip>": {"os": [...], "ports": {...}}}},
          "smb":   {"status": "completed", "result": {"anonymous_access": bool, "shares": {...}}},
          "ad":    {"status": "completed", "result": {"users": [...], "domain_admins": [...],
                                                        "kerberoastable": [...], "asrep_roastable": [...]}},
          "vuln":  {"status": "completed", "result": {...}}
        },
        "security_findings": [
          {"severity": "Critical", "category": "...", "title": "...",
           "detail": "...", "recommendation": "..."}
        ]
      },
      ...
    }
    """

    def __init__(self, output_path, targets_data, log=None,
                 engagement_name="ANCScan Security Assessment",
                 pentester_name="N/A", client_name=None, report_id=None):
        self.output_path = output_path
        self.targets_data = targets_data or {}
        self.log = log or []
        self.engagement_name = engagement_name
        self.pentester_name = pentester_name or "N/A"
        self.client_name = client_name
        self.generated_at = datetime.datetime.now()
        self.report_id = report_id or self.generated_at.strftime("ANCSCAN-%Y%m%d-%H%M%S")

        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(
            name='TitleCustom', fontSize=26, leading=30, spaceAfter=10,
            textColor=NAVY, alignment=TA_CENTER
        ))
        self.styles.add(ParagraphStyle(
            name='SubtitleCustom', parent=self.styles['Normal'], fontSize=13,
            leading=16, alignment=TA_CENTER, textColor=colors.HexColor("#444444"),
            spaceAfter=4
        ))
        self.styles.add(ParagraphStyle(
            name='CenterNormal', parent=self.styles['Normal'], alignment=TA_CENTER
        ))
        self.styles.add(ParagraphStyle(
            name='CoverMeta', parent=self.styles['Normal'], fontSize=10.5,
            leading=15, alignment=TA_LEFT
        ))
        self.styles.add(ParagraphStyle(
            name='CoverMetaLabel', parent=self.styles['CoverMeta'],
            textColor=NAVY,
        ))
        self.styles.add(ParagraphStyle(
            name='ConfidentialNotice', parent=self.styles['Normal'], fontSize=8,
            leading=11, alignment=TA_CENTER, textColor=colors.HexColor("#777777")
        ))
        self.styles.add(ParagraphStyle(
            name='FindingTitle', parent=self.styles['Heading2'], spaceBefore=14
        ))
        self.styles.add(ParagraphStyle(
            name='Mono', fontName='Courier', fontSize=8, leading=10
        ))
        self.styles.add(ParagraphStyle(
            name='CellText', parent=self.styles['Normal'], fontSize=8, leading=10
        ))
        self.styles.add(ParagraphStyle(
            name='CellTextHeader', parent=self.styles['CellText'],
            textColor=colors.white, fontName='Helvetica-Bold'
        ))

        self.elements = []
        self._all_findings = self._flatten_findings()

    # ---------------------------------------------------------------
    # data helpers
    # ---------------------------------------------------------------
    def _flatten_findings(self):
        rows = []
        for ip, t in self.targets_data.items():
            for f in (t.get("security_findings") or []):
                row = dict(f)
                row["host"] = ip
                rows.append(row)
        rank = {s: i for i, s in enumerate(SEV_ORDER)}
        rows.sort(key=lambda r: rank.get(r.get("severity"), len(SEV_ORDER)))
        return rows

    def _severity_counts(self):
        counts = {s: 0 for s in SEV_ORDER}
        for f in self._all_findings:
            if f.get("severity") in counts:
                counts[f["severity"]] += 1
        return counts

    def _worst_severity(self):
        for s in SEV_ORDER:
            if any(f.get("severity") == s for f in self._all_findings):
                return s
        return None

    def _host_ports(self, ip):
        t = self.targets_data.get(ip, {})
        recon = (t.get("modules", {}).get("recon") or {}).get("result") or {}
        host = recon.get(ip) or {}
        return host.get("ports") or {}

    def _host_os(self, ip):
        t = self.targets_data.get(ip, {})
        recon = (t.get("modules", {}).get("recon") or {}).get("result") or {}
        host = recon.get(ip) or {}
        os_list = host.get("os") or []
        return os_list[0]["name"] if os_list else "Unknown"

    @staticmethod
    def _escape(text):
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def _cell(self, text, header=False):
        """Wrap raw cell text in a Paragraph so long content wraps inside the
        cell instead of overflowing into neighboring columns."""
        style = self.styles['CellTextHeader'] if header else self.styles['CellText']
        return Paragraph(self._escape(text), style)

    def _styled_table(self, data, col_widths, severity_col=None, findings=None):
        """Build a Table where every cell is a wrapped Paragraph, with a
        standard navy header row and grey grid."""
        wrapped = [[self._cell(cell, header=True) for cell in data[0]]]
        for row in data[1:]:
            wrapped.append([self._cell(cell) for cell in row])

        table = Table(wrapped, colWidths=col_widths, repeatRows=1)
        style = [
            ('BACKGROUND', (0, 0), (-1, 0), NAVY),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f8")]),
        ]
        if severity_col is not None and findings:
            for row_idx, f in enumerate(findings, start=1):
                color = SEV_COLOR.get(f.get("severity"))
                if color:
                    style.append(('TEXTCOLOR', (severity_col, row_idx), (severity_col, row_idx), color))
        table.setStyle(TableStyle(style))
        return table

    # ---------------------------------------------------------------
    # 0. cover page
    # ---------------------------------------------------------------
    def add_cover_page(self):
        targets_list = ", ".join(self.targets_data.keys()) or "N/A"

        self.elements.append(Spacer(1, 4.5 * cm))
        self.elements.append(Paragraph(self._escape(self.engagement_name), self.styles['TitleCustom']))
        self.elements.append(Paragraph("Penetration Testing Report — Confidential", self.styles['SubtitleCustom']))
        self.elements.append(Spacer(1, 0.4 * cm))
        self.elements.append(HRFlowable(width="60%", thickness=1.2, color=NAVY, hAlign='CENTER'))
        self.elements.append(Spacer(1, 1.4 * cm))

        meta_rows = [
            ["Client:", self.client_name or "N/A"],
            ["Target(s) in scope:", targets_list],
            ["Prepared by:", self.pentester_name],
            ["Report ID:", self.report_id],
            ["Report generated:", self.generated_at.strftime("%Y-%m-%d")],
            ["Generation time:", self.generated_at.strftime("%H:%M:%S")],
        ]
        meta_data = [
            [Paragraph(self._escape(label), self.styles['CoverMetaLabel']),
             Paragraph(self._escape(value), self.styles['CoverMeta'])]
            for label, value in meta_rows
        ]
        meta_table = Table(meta_data, colWidths=[5.5 * cm, 9.5 * cm], hAlign='CENTER')
        meta_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW', (0, 0), (-1, -2), 0.4, colors.HexColor("#dddddd")),
        ]))
        self.elements.append(meta_table)

        self.elements.append(Spacer(1, 3 * cm))
        self.elements.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#cccccc")))
        self.elements.append(Spacer(1, 0.3 * cm))
        self.elements.append(Paragraph(
            "This document contains confidential and proprietary information prepared exclusively "
            "for the recipient client. It is intended solely to support remediation of the security "
            "issues described herein and must not be distributed outside the client organization "
            "without prior written authorization.",
            self.styles['ConfidentialNotice']
        ))
        self.elements.append(PageBreak())

    # ---------------------------------------------------------------
    # 1. executive summary
    # ---------------------------------------------------------------
    def add_executive_summary(self):
        self.elements.append(Paragraph("1. Executive Summary", self.styles['Heading1']))

        counts = self._severity_counts()
        worst = self._worst_severity()
        rating = RISK_RATING_BY_WORST_SEVERITY.get(worst, "Low") if worst else "No findings recorded"

        num_hosts = len(self.targets_data)
        total_findings = len(self._all_findings)

        summary_text = (
            f"This assessment covered {num_hosts} target host(s). "
            f"A total of {total_findings} finding(s) were identified: "
            f"{counts['Critical']} Critical, {counts['High']} High, "
            f"{counts['Medium']} Medium, {counts['Low']} Low, and {counts['Info']} Informational. "
            f"Based on the highest severity finding observed, the overall risk rating for this "
            f"engagement is <b>{rating}</b>."
        )
        self.elements.append(Paragraph(summary_text, self.styles['Normal']))
        self.elements.append(Spacer(1, 0.5 * cm))

        if total_findings:
            self.elements.append(Paragraph("Prioritized Recommendations", self.styles['Heading2']))
            seen = set()
            for f in self._all_findings:
                rec = f.get("recommendation")
                if rec and rec not in seen:
                    seen.add(rec)
                    self.elements.append(Paragraph(f"• {self._escape(rec)}", self.styles['Normal']))
        self.elements.append(Spacer(1, 1 * cm))

    # ---------------------------------------------------------------
    # 2. scope
    # ---------------------------------------------------------------
    def add_scope(self):
        self.elements.append(Paragraph("2. Scope", self.styles['Heading1']))

        if not self.targets_data:
            self.elements.append(Paragraph("No targets were recorded for this engagement.", self.styles['Normal']))
            self.elements.append(Spacer(1, 1 * cm))
            return

        data = [["Target IP", "Domain", "OS", "Open Ports / Services"]]
        for ip, t in self.targets_data.items():
            domain = t.get("domain", "-") or "-"
            os_name = self._host_os(ip)
            ports = self._host_ports(ip)
            svc_str = ", ".join(f"{p}/{info.get('service', '?')}" for p, info in ports.items()) or "None discovered"
            data.append([ip, domain, os_name, svc_str])

        table = self._styled_table(data, col_widths=[2.8 * cm, 2.8 * cm, 3.4 * cm, 8 * cm])
        self.elements.append(table)
        self.elements.append(Spacer(1, 1 * cm))

    # ---------------------------------------------------------------
    # 3. methodology
    # ---------------------------------------------------------------
    def add_methodology(self):
        self.elements.append(Paragraph("3. Methodology", self.styles['Heading1']))

        ran = set()
        for t in self.targets_data.values():
            for mod_name, mod in (t.get("modules") or {}).items():
                if mod.get("status") == "completed":
                    ran.add(mod_name)

        lines = []
        if "recon" in ran:
            lines.append(
                "Reconnaissance: Port, service, and OS fingerprinting was performed against "
                "each in-scope target to enumerate the attack surface."
            )
        if "smb" in ran:
            lines.append(
                "SMB Enumeration: SMB shares were enumerated on each target, including a check "
                "for anonymous/unauthenticated access."
            )
        if "ad" in ran:
            lines.append(
                "Active Directory Enumeration: Domain user accounts, domain administrators, "
                "and accounts vulnerable to Kerberoasting or AS-REP roasting were enumerated."
            )
        if "vuln" in ran:
            lines.append(
                "Vulnerability Mapping: Discovered services and configurations were checked "
                "against known vulnerabilities to identify exploitable weaknesses."
            )
        if not lines:
            lines.append("No enumeration modules reported a completed status for this engagement.")

        for line in lines:
            self.elements.append(Paragraph(f"• {line}", self.styles['Normal']))
        self.elements.append(Spacer(1, 1 * cm))

    # ---------------------------------------------------------------
    # 4. findings summary table
    # ---------------------------------------------------------------
    def add_findings_summary_table(self):
        self.elements.append(Paragraph("4. Findings Summary Table", self.styles['Heading1']))

        if not self._all_findings:
            self.elements.append(Paragraph("No findings were recorded.", self.styles['Normal']))
            self.elements.append(Spacer(1, 1 * cm))
            return

        data = [["ID", "Finding", "Severity", "Host", "Impact"]]
        for i, f in enumerate(self._all_findings, start=1):
            data.append([
                f"F-{i:03d}",
                f.get("title", ""),
                f.get("severity", ""),
                f.get("host", ""),
                f.get("detail", "")[:120] + ("…" if len(f.get("detail", "")) > 120 else ""),
            ])

        table = self._styled_table(
            data,
            col_widths=[1.6 * cm, 4.2 * cm, 2.2 * cm, 2.6 * cm, 6.4 * cm],
            severity_col=2,
            findings=self._all_findings,
        )
        self.elements.append(table)
        self.elements.append(Spacer(1, 1 * cm))

    # ---------------------------------------------------------------
    # 5. detailed findings
    # ---------------------------------------------------------------
    def add_detailed_findings(self):
        self.elements.append(Paragraph("5. Detailed Findings", self.styles['Heading1']))

        if not self._all_findings:
            self.elements.append(Paragraph("No findings were recorded.", self.styles['Normal']))
            self.elements.append(Spacer(1, 1 * cm))
            return

        for i, f in enumerate(self._all_findings, start=1):
            self.elements.append(Paragraph(
                f"F-{i:03d}: {self._escape(f.get('title', 'Untitled Finding'))}", self.styles['FindingTitle']
            ))
            self.elements.append(Paragraph(f"<b>Severity:</b> {self._escape(f.get('severity', 'N/A'))}", self.styles['Normal']))
            self.elements.append(Paragraph(f"<b>Host:</b> {self._escape(f.get('host', 'N/A'))}", self.styles['Normal']))
            self.elements.append(Paragraph(f"<b>Description:</b> {self._escape(f.get('detail', 'N/A'))}", self.styles['Normal']))
            self.elements.append(Paragraph(f"<b>Evidence:</b> {self._escape(f.get('category', 'N/A'))}", self.styles['Normal']))
            self.elements.append(Paragraph(f"<b>Recommendation:</b> {self._escape(f.get('recommendation', 'N/A'))}", self.styles['Normal']))
            self.elements.append(Spacer(1, 0.4 * cm))

    # ---------------------------------------------------------------
    # 6. attack path
    # ---------------------------------------------------------------
    def add_attack_path(self):
        self.elements.append(Paragraph("6. Attack Path", self.styles['Heading1']))

        narrative_points = []
        for ip, t in self.targets_data.items():
            smb = (t.get("modules", {}).get("smb") or {}).get("result") or {}
            ad = (t.get("modules", {}).get("ad") or {}).get("result") or {}

            if smb.get("anonymous_access"):
                narrative_points.append(
                    f"{ip} allows anonymous SMB access, which could let an attacker enumerate "
                    f"shares and files without credentials."
                )
            if ad.get("kerberoastable"):
                narrative_points.append(
                    f"{ip} has Kerberoastable account(s) ({', '.join(ad['kerberoastable'])}), "
                    f"which could be used to obtain crackable service ticket hashes."
                )
            if ad.get("asrep_roastable"):
                narrative_points.append(
                    f"{ip} has AS-REP roastable account(s) ({', '.join(ad['asrep_roastable'])}), "
                    f"allowing offline password cracking without prior authentication."
                )

        crit_or_high = [f for f in self._all_findings if f.get("severity") in ("Critical", "High")]
        if crit_or_high:
            titles = ", ".join(sorted({f.get("title", "") for f in crit_or_high}))
            narrative_points.append(
                f"Critical/High severity findings ({titles}) could be leveraged as an initial "
                f"foothold before pivoting to the conditions noted above."
            )

        if narrative_points:
            for p in narrative_points:
                self.elements.append(Paragraph(f"• {self._escape(p)}", self.styles['Normal']))
        else:
            self.elements.append(Paragraph(
                "No chainable combination of findings was identified from the available data.",
                self.styles['Normal']
            ))
        self.elements.append(Spacer(1, 1 * cm))

    # ---------------------------------------------------------------
    # 7. remediation plan
    # ---------------------------------------------------------------
    def add_remediation_plan(self):
        self.elements.append(Paragraph("7. Remediation Plan", self.styles['Heading1']))

        if not self._all_findings:
            self.elements.append(Paragraph("No remediation items — no findings were recorded.", self.styles['Normal']))
            self.elements.append(Spacer(1, 1 * cm))
            return

        data = [["Priority", "Finding", "Recommendation"]]
        for i, f in enumerate(self._all_findings, start=1):
            data.append([
                f.get("severity", ""),
                f.get("title", ""),
                f.get("recommendation", "N/A"),
            ])
        table = self._styled_table(data, col_widths=[2.3 * cm, 4.7 * cm, 10 * cm])
        self.elements.append(table)
        self.elements.append(Spacer(1, 1 * cm))

    # ---------------------------------------------------------------
    # 8. appendix
    # ---------------------------------------------------------------
    def add_appendix(self):
        self.elements.append(PageBreak())
        self.elements.append(Paragraph("8. Appendix", self.styles['Heading1']))

        self.elements.append(Paragraph("8.1 Raw Port Scan Data", self.styles['Heading2']))
        any_ports = False
        for ip in self.targets_data:
            ports = self._host_ports(ip)
            if not ports:
                continue
            any_ports = True
            self.elements.append(Paragraph(
                f"Host: {self._escape(ip)}",
                self.styles['Heading3'] if 'Heading3' in self.styles else self.styles['Heading2']
            ))
            data = [["Port", "State", "Service", "Version"]]
            for port, info in ports.items():
                data.append([str(port), info.get("state", ""), info.get("service", ""), info.get("version", "-")])
            table = self._styled_table(data, col_widths=[2.3 * cm, 2.3 * cm, 4 * cm, 7.4 * cm])
            self.elements.append(table)
            self.elements.append(Spacer(1, 0.4 * cm))
        if not any_ports:
            self.elements.append(Paragraph("No raw port scan data was recorded.", self.styles['Normal']))

        if self.log:
            self.elements.append(Paragraph("8.2 Execution Log", self.styles['Heading2']))
            for line in self.log:
                self.elements.append(Paragraph(self._escape(line), self.styles['Mono']))

    # ---------------------------------------------------------------
    # header / footer (page numbers + confidentiality strip)
    # ---------------------------------------------------------------
    def _draw_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#cccccc"))
        canvas.setLineWidth(0.5)
        canvas.line(2 * cm, 1.5 * cm, A4[0] - 2 * cm, 1.5 * cm)

        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor("#777777"))
        canvas.drawString(2 * cm, 1.1 * cm, f"{self.engagement_name} — Confidential")
        canvas.drawRightString(A4[0] - 2 * cm, 1.1 * cm, f"Page {doc.page}")
        canvas.drawCentredString(
            A4[0] / 2, 1.1 * cm,
            f"Generated {self.generated_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        canvas.restoreState()

    # ---------------------------------------------------------------
    # build
    # ---------------------------------------------------------------
    def build(self):
        self.add_cover_page()
        self.add_executive_summary()
        self.add_scope()
        self.add_methodology()
        self.add_findings_summary_table()
        self.add_detailed_findings()
        self.add_attack_path()
        self.add_remediation_plan()
        self.add_appendix()

        doc = SimpleDocTemplate(
            self.output_path, pagesize=A4,
            topMargin=2 * cm, bottomMargin=2.2 * cm,
        )
        doc.build(
            self.elements,
            onFirstPage=self._draw_footer,
            onLaterPages=self._draw_footer,
        )
        print(f"[*] Report written to {self.output_path}")


if __name__ == "__main__":
    demo_targets = {
        "192.168.56.20": {
            "domain": "ancs.local",
            "modules": {
                "recon": {"status": "completed", "result": {
                    "192.168.56.20": {
                        "os": [{"name": "Windows Server 2016"}],
                        "ports": {
                            "445": {"state": "open", "service": "microsoft-ds", "version": "-"},
                            "389": {"state": "open", "service": "ldap", "version": "-"},
                        }
                    }
                }},
                "smb": {"status": "completed", "result": {"anonymous_access": True, "shares": {"NETLOGON": []}}},
                "ad": {"status": "completed", "result": {
                    "users": ["alice", "bob"], "domain_admins": ["admin"],
                    "kerberoastable": ["svc_sql"], "asrep_roastable": []
                }},
                "vuln": {"status": "completed", "result": {}},
            },
            "security_findings": [
                {"severity": "Critical", "category": "SMB", "title": "EternalBlue (MS17-010)",
                 "detail": "Host is vulnerable to CVE-2017-0144 via SMBv1.",
                 "recommendation": "Patch immediately per MS17-010 and disable SMBv1."},
                {"severity": "Medium", "category": "LDAP", "title": "Unencrypted LDAP exposed",
                 "detail": "LDAP service on port 389 does not enforce signing.",
                 "recommendation": "Enforce LDAP signing and channel binding."},
            ],
        }
    }
    reporter = Reporter(
        "output/ancscan_report.pdf", demo_targets,
        log=["[*] Recon started", "[+] Recon completed"],
        pentester_name="Zaineb",
        client_name="ANCS Corp",
    )
    reporter.build()
