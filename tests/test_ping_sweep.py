"""
test_ping_sweep.py — Day 6 learning script: host discovery via nmap ping sweep.
"""
import nmap

nm = nmap.PortScanner()
nm.scan(hosts='192.168.56.0/24', arguments='-sn')

print("[*] Live hosts found:")
for host in nm.all_hosts():
    print(f"  {host} - {nm[host].state()}")
