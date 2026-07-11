import nmap
import argparse
from rich.console import Console
from rich.table import Table

console = Console()


class Recon:
    def __init__(self, target, deep=False):
        self.target = target
        self.nm = nmap.PortScanner()
        self.args = '-sV -sC -O' + (' -p-' if deep else '')

    def discover_hosts(self):
        """Ping sweep only -- finds which hosts are alive, no ports touched."""
        print(f'[*] Ping sweep on {self.target} ...')
        self.nm.scan(hosts=self.target, arguments='-sn')

        live_hosts = {}
        for host in self.nm.all_hosts():
            live_hosts[host] = {
                'state': self.nm[host].state(),
                'hostname': self.nm[host].hostname() or 'unknown'
            }
        return live_hosts

    def display_hosts(self, live_hosts):
        """Print live hosts as a clean Rich table."""
        table = Table(title="Live Hosts")
        table.add_column("IP Address", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Hostname", style="yellow")

        for host, info in live_hosts.items():
            table.add_row(host, info['state'], info['hostname'])

        console.print(table)

    def run(self):
        print(f'[*] Scanning {self.target} ...')
        self.nm.scan(hosts=self.target, arguments=self.args)
        return self.parse()

    def parse(self):
        results = {}
        for host in self.nm.all_hosts():
            results[host] = {
                'state': self.nm[host].state(),
                'os': self.nm[host].get('osmatch', []),
                'ports': {}
            }
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    info = self.nm[host][proto][port]
                    results[host]['ports'][port] = {
                        'state': info['state'],
                        'service': info['name'],
                        'version': info.get('version', '')
                    }
        return results


def format_report(results):
    output = ""
    for host, data in results.items():
        output += f"{host}:\n"
        if data['os']:
            os_name = data['os'][0]['name']
        else:
            os_name = "Unknown"
        output += f"OS : {os_name}\n"
        for port, info in data['ports'].items():
            service = info['service']
            state = info['state']
            version = info['version'] if info['version'] else "Unknown"
            output += f"Port {port} : {state} | {service} | {version}\n"
        output += "\n"
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--discover-only", action="store_true")
    args = parser.parse_args()

    recon = Recon(args.target, args.deep)

    if args.discover_only:
        hosts = recon.discover_hosts()
        recon.display_hosts(hosts)
    else:
        results = recon.run()
        print(format_report(results))
