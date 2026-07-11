"""
test_service_scan.py — Day 6 learning script: service/version detection.
"""
import nmap

nm = nmap.PortScanner()
nm.scan(hosts='192.168.56.20', arguments='-sV')

for host in nm.all_hosts():
    print(f"[*] Host: {host}")
    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            info = nm[host][proto][port]
            print(f"  {port}/{proto} - {info['name']} {info.get('version','')}")
