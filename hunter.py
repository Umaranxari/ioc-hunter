import re
import json
import argparse
import sys
from datetime import datetime

# ANSI Colors for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def load_signatures(path):
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            return data['signatures']
    except FileNotFoundError:
        print(f"[-] Error: Signature file {path} not found.")
        sys.exit(1)

def scan_line(line, compiled_sigs):
    hits = []
    for sig_name, regex, sev in compiled_sigs:
        if regex.search(line):
            hits.append((sig_name, sev))
    return hits

def main():
    parser = argparse.ArgumentParser(description="IOC-Hunter: Post-Compromise Log Analysis Tool")
    parser.add_argument("logfile", help="Path to server access.log")
    parser.add_argument("--signatures", "-s", default="signatures.json", help="Path to signatures file")
    args = parser.parse_args()

    print(f"[*] Loading signatures from {args.signatures}...")
    signatures = load_signatures(args.signatures)
    
    # Pre-compile regex for performance
    compiled_sigs = []
    for sig in signatures:
        try:
            compiled_sigs.append((sig['name'], re.compile(sig['pattern'], re.IGNORECASE), sig['severity']))
        except re.error:
            print(f"[-] Invalid Regex: {sig['pattern']}")

    print(f"[*] Compiled {len(compiled_sigs)} detection rules.")
    print(f"[*] Scanning {args.logfile}...\n")

    try:
        with open(args.logfile, 'r') as f:
            line_count = 0
            detected_count = 0
            
            for line in f:
                line_count += 1
                hits = scan_line(line, compiled_sigs)
                
                if hits:
                    detected_count += 1
                    # Extract timestamp if possible (Common Log Format)
                    ts = line.split()[3].strip('[') if len(line.split()) > 3 else "Unknown Time"
                    
                    for name, sev in hits:
                        color = RED if sev == "CRITICAL" else YELLOW
                        print(f"{color}[!] ALERT: {name} detected{RESET}")
                        print(f"    Sev: {sev} | Line: {line_count} | Time: {ts}")
                        print(f"    Payload: {line.strip()[:100]}...\n")

        print(f"[*] Scan Complete. Scanned {line_count} lines. Found {detected_count} IOCs.")
        
    except FileNotFoundError:
        print("[-] Log file not found.")

if __name__ == "__main__":
    main()
