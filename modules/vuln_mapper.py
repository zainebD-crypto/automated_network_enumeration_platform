"""
vuln_mapper.py — Lightweight vulnerability mapping module for ANCScan.

Takes recon.py's service/version output and cross-references it against a
small local mapping of known misconfigurations. This is a starter
implementation; Week 3 of the roadmap replaces this with a real local CVE
database built from NVD data.
"""

KNOWN_ISSUES = {
    'microsoft-ds': [{
        'title': 'SMB service exposed', 'severity': 'Info',
        'note': 'Verify SMB signing is enforced and SMBv1 is disabled unless required.'
    }],
    'netbios-ssn': [{
        'title': 'NetBIOS session service exposed', 'severity': 'Low',
        'note': 'Legacy protocol; can leak hostnames/domain info via NBT-NS.'
    }],
    'ldap': [{
        'title': 'Unencrypted LDAP exposed', 'severity': 'Medium',
        'note': 'Enforce LDAP signing and channel binding; disable plaintext binds.'
    }],
    'kerberos-sec': [{
        'title': 'Kerberos exposed', 'severity': 'Info',
        'note': 'Enables Kerberoasting/AS-REP Roasting checks; verify via enum_ad.py.'
    }],
    'http': [{
        'title': 'HTTP service exposed (possible WinRM)', 'severity': 'Medium',
        'note': 'If this is WinRM (5985), confirm it does not accept unencrypted remote PowerShell sessions.'
    }],
}


class VulnMapper:
    def __init__(self, recon_results):
        self.recon_results = recon_results

    def map_host(self, host_data):
        findings = []
        for port, info in host_data.get('ports', {}).items():
            service = info.get('service', '')
            for key, issues in KNOWN_ISSUES.items():
                if key in service:
                    for issue in issues:
                        findings.append({'port': port, 'service': service, **issue})
        return findings

    def run(self):
        return {host: self.map_host(data) for host, data in self.recon_results.items()}


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            recon_data = json.load(f)
    else:
        recon_data = json.load(sys.stdin)

    mapper = VulnMapper(recon_data)
    print(json.dumps(mapper.run(), indent=2))
