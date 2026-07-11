"""
test_port_scan.py — Day 6 learning script: basic TCP port scan.
"""
import nmap

nm = nmap.PortScanner()
nm.scan(hosts='192.168.56.20', arguments='-p 1-1000')

for host in nm.all_hosts():
    print(f"[*] Host: {host} ({nm[host].state()})")
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in sorted(ports):
            state = nm[host][proto][port]['state']
            print(f"  Port {port}/{proto}: {state}")
