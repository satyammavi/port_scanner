
import nmap
import argparse
import json
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

# Define the banner
banner = (Fore.GREEN + '''
  OOOOOOO                                        
                       __                          
  ___________ _/  |_ ___.__._____    _____  
 /  ___/\__  \\   __<   |  |\__  \  /     \ 
 \___ \  / __ \|  |  \___  | / __ \|  Y Y  \\
/____  >(____  /__|  / ____|(____  /__|_|  /
     \/      \/      \/          \/      \/              


                                MADE BY SATYAM
''')

def scan_network(target, options):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments=options)
        return nm
    except nmap.PortScannerError as e:
        print(f"Error during scan: {e}")
        return None

def display_results(nm):
    results = []
    for host in nm.all_hosts():
        host_info = {
            'Host': host,
            'Hostname': nm[host].hostname(),
            'State': nm[host].state(),
            'Protocols': {}
        }
        if 'osmatch' in nm[host]:
            host_info['OS'] = [
                {'OS Family': match['osclass'][0]['osfamily'], 
                 'OS Gen': match['osclass'][0]['osgen'], 
                 'Accuracy': match['accuracy']}
                for match in nm[host]['osmatch'] if 'osclass' in match
            ]
        for proto in nm[host].all_protocols():
            proto_info = {}
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                proto_info[port] = {
                    'State': nm[host][proto][port]['state'],
                    'Service': nm[host][proto][port].get('name', 'unknown'),
                    'Product': nm[host][proto][port].get('product', 'unknown'),
                    'Version': nm[host][proto][port].get('version', 'unknown')
                }
            host_info['Protocols'][proto] = proto_info

        if 'hostscript' in nm[host]:
            host_info['Vulnerabilities'] = [
                {'ID': script['id'], 'Output': script['output']}
                for script in nm[host]['hostscript']
            ]

        results.append(host_info)
        print(json.dumps(host_info, indent=2))
    return results

def save_results(results, filename):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {filename}")

if __name__ == "__main__":
    # Print the banner
    print(banner.upper())
    
    parser = argparse.ArgumentParser(description="Advanced Network Scanner Tool using Nmap")
    parser.add_argument('target', type=str, help="Target IP address or range (e.g., 192.168.1.0/24)")
    parser.add_argument('--ping', action='store_true', help="Perform a ping scan")
    parser.add_argument('--tcp', action='store_true', help="Perform a TCP port scan")
    parser.add_argument('--udp', action='store_true', help="Perform a UDP port scan")
    parser.add_argument('--os', action='store_true', help="Perform OS detection")
    parser.add_argument('--version', action='store_true', help="Perform version detection")
    parser.add_argument('--ports', type=str, help="Specify ports to scan (e.g., 22,80,443)")
    parser.add_argument('--aggressive', action='store_true', help="Perform an aggressive scan")
    parser.add_argument('--traceroute', action='store_true', help="Perform a traceroute")
    parser.add_argument('--vuln', action='store_true', help="Perform a vulnerability scan")
    parser.add_argument('--output', type=str, help="Save the scan results to a file (e.g., results.json)")

    args = parser.parse_args()

    scan_options = []

    if args.ping:
        scan_options.append('-sn')
    if args.tcp:
        scan_options.append('-sT')
    if args.udp:
        scan_options.append('-sU')
    if args.os:
        scan_options.append('-O')
    if args.version:
        scan_options.append('-sV')
    if args.ports:
        scan_options.append(f'-p {args.ports}')
    if args.aggressive:
        scan_options.append('-A')
    if args.traceroute:
        scan_options.append('--traceroute')
    if args.vuln:
        scan_options.append('--script vuln')

    if not scan_options:
        print("No scan type specified. Use --ping, --tcp, --udp, --os, --version, --ports, --aggressive, --traceroute, or --vuln.")
        exit(1)
    
    nm = scan_network(args.target, ' '.join(scan_options))
    if nm:
        results = display_results(nm)
        if args.output:
            save_results(results, args.output)
