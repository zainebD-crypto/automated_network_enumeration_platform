"""
enum_smb.py — SMB enumeration module for ANCScan.

Connects to a target's SMB service (port 445) and enumerates:
- Available shares (with an anonymous/null session attempt)
- OS / server info exposed via SMB negotiation
- Listing of files at the root of accessible shares

Relies on impacket's SMBConnection.
"""
from impacket.smbconnection import SMBConnection


class SMBEnum:
    def __init__(self, target, username='', password='', domain=''):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.conn = None

    def connect(self):
        """Establish an SMB connection. Empty creds = anonymous/null session attempt."""
        self.conn = SMBConnection(self.target, self.target)
        self.conn.login(self.username, self.password, self.domain)
        return self.conn

    def get_server_info(self):
        if not self.conn:
            self.connect()
        return {
            'server_os': self.conn.getServerOS(),
            'server_name': self.conn.getServerName(),
            'server_domain': self.conn.getServerDomain(),
            'signing_required': self.conn.isSigningRequired(),
        }

    def list_shares(self):
        if not self.conn:
            self.connect()
        shares = []
        for share in self.conn.listShares():
            shares.append(share['shi1_netname'][:-1])
        return shares

    def list_share_contents(self, share_name, path='*'):
        if not self.conn:
            self.connect()
        entries = []
        try:
            for f in self.conn.listPath(share_name, path):
                name = f.get_longname()
                if name not in ('.', '..'):
                    entries.append({
                        'name': name,
                        'is_directory': f.is_directory(),
                        'size': f.get_filesize()
                    })
        except Exception as e:
            entries.append({'error': str(e)})
        return entries

    def check_anonymous_access(self):
        try:
            test_conn = SMBConnection(self.target, self.target)
            test_conn.login('', '')
            test_conn.close()
            return True
        except Exception:
            return False

    def run(self):
        results = {'target': self.target}
        results['anonymous_access'] = self.check_anonymous_access()
        try:
            self.connect()
            results['server_info'] = self.get_server_info()
            shares = self.list_shares()
            results['shares'] = {}
            for share in shares:
                if share.upper() in ('IPC$', 'ADMIN$', 'C$'):
                    continue
                results['shares'][share] = self.list_share_contents(share)
        except Exception as e:
            results['error'] = str(e)
        return results


if __name__ == "__main__":
    import json
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--username", default='')
    parser.add_argument("--password", default='')
    parser.add_argument("--domain", default='')
    args = parser.parse_args()

    enum = SMBEnum(args.target, args.username, args.password, args.domain)
    results = enum.run()
    print(json.dumps(results, indent=2, default=str))
