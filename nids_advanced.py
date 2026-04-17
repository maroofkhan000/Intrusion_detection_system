#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, conf, get_if_addr, send, getmacbyip, Ether, get_if_hwaddr
import time
import threading
import re
import sys
import os
from collections import defaultdict, deque
from colorama import Fore, Style, init
import argparse
import json
from datetime import datetime
import sys
import os
import signal

# Track Ctrl+C presses
interrupt_count = 0

def signal_handler(sig, frame):
    global interrupt_count
    interrupt_count += 1
    if interrupt_count > 1:
        print("\n[!] Emergency shutdown initiated. Exiting...")
        os._exit(1)
    print("\n\n[*] Shutting down gracefully... (Press Ctrl+C again to force quit)")

# Bind signal
signal.signal(signal.SIGINT, signal_handler)

init(autoreset=True)

# ================= CONFIGURATION =================
SCAN_THRESHOLD = 15          # Ports touched before triggering alert
FLOOD_THRESHOLD = 100        # SYN packets per second
ALERT_COOLDOWN = 5           # Seconds between duplicate alerts
STATS_INTERVAL = 15          # Stats display interval
TIME_WINDOW = 2              # Seconds for rate calculations

# ================= COLORS =================
C = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.MAGENTA + Style.BRIGHT,
    "med": Fore.YELLOW + Style.BRIGHT,
    "low": Fore.CYAN,
    "info": Fore.GREEN,
    "rst": Style.RESET_ALL,
}

# ================= DETECTION ENGINE =================
class AdvancedNIDS:
    def __init__(self, iface, bpf, dry_run, log_file, promiscuous=False):
        self.iface = iface
        self.bpf = bpf
        self.dry_run = dry_run
        self.log_file = log_file
        self.promiscuous = promiscuous  # Monitor ALL network traffic

        try:
            self.local_ip = get_if_addr(iface)
            self.local_mac = get_if_hwaddr(iface)
        except:
            self.local_ip = "0.0.0.0"
            self.local_mac = "00:00:00:00:00:00"
            print(f"[!] Warning: Could not get IP/MAC for {iface}")

        # Active Monitoring
        self.target_ip = None
        self.gateway_ip = None
        self.stop_spoofing = threading.Event()

        # Statistics
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "arp_packets": 0,
            "alerts": 0,
            "start_time": time.time()
        }

        # Detection data structures
        self.alert_history = {}
        
        # Port scan detection
        self.port_scan_tracker = defaultdict(lambda: {
            "ports": set(),
            "first_seen": time.time(),
            "syn_count": 0
        })
        
        # SYN flood detection
        self.syn_timestamps = defaultdict(deque)
        
        # Connection tracking
        self.established_conns = defaultdict(set)
        
        # ARP spoofing detection
        self.arp_table = {}
        
        # Payload analysis
        self.suspicious_patterns = [
            (re.compile(rb'(?i)(select|union|insert|update|delete).*(from|into|where)', re.IGNORECASE), "SQL Injection"),
            (re.compile(rb'<script[^>]*>.*?</script>', re.IGNORECASE), "XSS Attempt"),
            (re.compile(rb'\.\./', re.IGNORECASE), "Path Traversal"),
            (re.compile(rb'(/etc/passwd|/etc/shadow)', re.IGNORECASE), "File Inclusion"),
            (re.compile(rb'cmd\.exe|/bin/sh|/bin/bash', re.IGNORECASE), "Command Injection"),
            (re.compile(rb'eval\(|exec\(|system\(', re.IGNORECASE), "Code Injection"),
        ]
        
        # Brute force detection
        self.auth_attempts = defaultdict(lambda: {
            "count": 0,
            "timestamps": deque(),
            "passwords": set()
        })
        
        # DNS tunneling detection
        self.dns_queries = defaultdict(deque)

    # ================= ALERT SYSTEM =================
    def alert(self, msg, src, dst="N/A", severity="med", details=""):
        key = (msg, src)
        now = time.time()

        # Cooldown check
        if key in self.alert_history:
            if now - self.alert_history[key] < ALERT_COOLDOWN:
                return

        self.alert_history[key] = now
        self.stats["alerts"] += 1

        # Format alert
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"\n{C[severity]}[{timestamp}] ALERT: {msg}{C['rst']}"
        alert_msg += f"\n   Source: {src}"
        if dst != "N/A":
            alert_msg += f" -> Destination: {dst}"
        if details:
            alert_msg += f"\n   Details: {details}"

        print(alert_msg)

        # Log to file
        if self.log_file:
            with open(self.log_file, 'a') as f:
                log_entry = {
                    "timestamp": timestamp,
                    "severity": severity,
                    "message": msg,
                    "source": src,
                    "destination": dst,
                    "details": details
                }
                f.write(json.dumps(log_entry) + "\n")

    # ================= TCP FLAG ANALYSIS =================
    def analyze_tcp_flags(self, pkt, src, dst):
        tcp = pkt[TCP]
        flags = tcp.flags
        sport = tcp.sport
        dport = tcp.dport

        # SYN packet (connection attempt or scan)
        if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
            self.handle_syn_packet(src, dst, dport)
        
        # SYN-ACK (response to connection)
        elif flags & 0x02 and flags & 0x10:  # SYN + ACK
            pass  # Normal server response
        
        # FIN scan detection
        elif flags & 0x01 and not (flags & 0x10):  # FIN without ACK
            self.alert("FIN Scan Detected", src, dst, "high", f"Target port: {dport}")
        
        # XMAS scan (FIN + PSH + URG)
        elif flags & 0x01 and flags & 0x08 and flags & 0x20:
            self.alert("XMAS Scan Detected", src, dst, "high", f"Target port: {dport}")
        
        # NULL scan (no flags)
        elif flags == 0:
            self.alert("NULL Scan Detected", src, dst, "high", f"Target port: {dport}")
        
        # PSH + ACK (data transfer)
        elif flags & 0x08 and flags & 0x10:  # PSH + ACK
            self.handle_data_packet(pkt, src, dst, dport)
            self.established_conns[src].add(dport)
        
        # RST packet (connection reset - could indicate failed scan)
        elif flags & 0x04:  # RST
            if src not in self.established_conns or dport not in self.established_conns[src]:
                self.port_scan_tracker[src]["syn_count"] += 1

    # ================= SYN PACKET HANDLER =================
    def handle_syn_packet(self, src, dst, dport):
        now = time.time()
        
        # Track port scan
        tracker = self.port_scan_tracker[src]
        tracker["ports"].add(dport)
        tracker["syn_count"] += 1
        
        # Port scan detection
        if len(tracker["ports"]) > SCAN_THRESHOLD:
            elapsed = now - tracker["first_seen"]
            ports_list = sorted(list(tracker["ports"]))[:10]  # First 10 ports
            details = f"Touched {len(tracker['ports'])} ports in {elapsed:.1f}s: {ports_list}..."
            self.alert("Port Scan Detected", src, dst, "high", details)
        
        # SYN flood detection
        self.syn_timestamps[src].append(now)
        
        # Clean old timestamps
        while self.syn_timestamps[src] and now - self.syn_timestamps[src][0] > TIME_WINDOW:
            self.syn_timestamps[src].popleft()
        
        # Check flood threshold
        syn_rate = len(self.syn_timestamps[src]) / TIME_WINDOW
        if syn_rate > FLOOD_THRESHOLD / TIME_WINDOW:
            details = f"{len(self.syn_timestamps[src])} SYN packets in {TIME_WINDOW}s ({syn_rate:.0f}/s)"
            self.alert("SYN Flood Attack", src, dst, "critical", details)

    # ================= DATA PACKET HANDLER =================
    def handle_data_packet(self, pkt, src, dst, dport):
        # Service detection
        if dport == 22:
            self.alert("SSH Connection Active", src, dst, "low", "Port 22")
        elif dport == 23:
            self.alert("Telnet Connection (Unencrypted)", src, dst, "med", "Port 23 - Consider disabling")
        elif dport == 21:
            self.alert("FTP Connection (Unencrypted)", src, dst, "med", "Port 21")
        elif dport in [80, 8080]:
            self.alert("HTTP Connection", src, dst, "low", f"Port {dport}")
        elif dport == 443:
            self.alert("HTTPS Connection", src, dst, "low", "Port 443")
        elif dport == 3306:
            self.alert("MySQL Connection", src, dst, "med", "Port 3306")
        elif dport == 5432:
            self.alert("PostgreSQL Connection", src, dst, "med", "Port 5432")
        elif dport == 1433:
            self.alert("MSSQL Connection", src, dst, "med", "Port 1433")
        elif dport == 3389:
            self.alert("RDP Connection", src, dst, "med", "Port 3389")
        elif dport == 445:
            self.alert("SMB Connection", src, dst, "med", "Port 445")
        
        # Payload inspection
        if pkt.haslayer(Raw):
            self.inspect_payload(pkt[Raw].load, src, dst, dport)

    # ================= PAYLOAD INSPECTION =================
    def inspect_payload(self, payload, src, dst, dport):
        try:
            for pattern, attack_type in self.suspicious_patterns:
                if pattern.search(payload):
                    preview = payload[:100].decode('utf-8', errors='ignore')
                    details = f"Port {dport} | Pattern: {attack_type} | Preview: {preview}"
                    self.alert(f"Malicious Payload Detected: {attack_type}", src, dst, "critical", details)
        except Exception as e:
            pass  # Binary data, skip

    # ================= ARP SPOOFING DETECTION =================
    def handle_arp(self, pkt):
        arp = pkt[ARP]
        ip = arp.psrc
        mac = arp.hwsrc
        
        # Check for ARP spoofing
        if ip in self.arp_table:
            if self.arp_table[ip] != mac:
                old_mac = self.arp_table[ip]
                details = f"IP {ip} changed MAC: {old_mac} -> {mac}"
                self.alert("ARP Spoofing Detected", ip, "N/A", "critical", details)
        
        self.arp_table[ip] = mac

    # ================= ICMP ANALYSIS =================
    def handle_icmp(self, pkt, src, dst):
        icmp = pkt[ICMP]
        
        # ICMP flood detection
        now = time.time()
        self.syn_timestamps[f"icmp_{src}"].append(now)
        
        while self.syn_timestamps[f"icmp_{src}"] and now - self.syn_timestamps[f"icmp_{src}"][0] > TIME_WINDOW:
            self.syn_timestamps[f"icmp_{src}"].popleft()
        
        if len(self.syn_timestamps[f"icmp_{src}"]) > 50:  # 50 ICMP packets in TIME_WINDOW
            details = f"{len(self.syn_timestamps[f'icmp_{src}'])} ICMP packets in {TIME_WINDOW}s"
            self.alert("ICMP Flood Detected", src, dst, "high", details)
        
        # Large ICMP packet (potential DoS)
        if len(pkt) > 1000:
            details = f"Packet size: {len(pkt)} bytes"
            self.alert("Large ICMP Packet", src, dst, "med", details)

    # ================= UDP ANALYSIS =================
    def handle_udp(self, pkt, src, dst):
        udp = pkt[UDP]
        dport = udp.dport
        
        # DNS tunneling detection (port 53)
        if dport == 53 and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if len(payload) > 512:  # Unusually large DNS query
                details = f"DNS query size: {len(payload)} bytes"
                self.alert("Potential DNS Tunneling", src, dst, "high", details)

    # ================= MAIN PACKET HANDLER =================
    def handle_packet(self, pkt):
        self.stats["total_packets"] += 1

        # ARP handling
        if pkt.haslayer(ARP):
            self.stats["arp_packets"] += 1
            self.handle_arp(pkt)
            return

        # IP layer required for further analysis
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        # Filter traffic based on mode
        if not self.promiscuous:
            # Host-based mode: only inbound traffic to this machine OR monitored target
            if dst != self.local_ip and src != self.target_ip and dst != self.target_ip:
                return
        else:
            # Network-wide mode: monitor all traffic
            # Skip outbound traffic from the NIDS machine itself
            if src == self.local_ip:
                return

        # TCP analysis
        if pkt.haslayer(TCP):
            self.stats["tcp_packets"] += 1
            self.analyze_tcp_flags(pkt, src, dst)
        
        # UDP analysis
        elif pkt.haslayer(UDP):
            self.stats["udp_packets"] += 1
            self.handle_udp(pkt, src, dst)
        
        # ICMP analysis
        elif pkt.haslayer(ICMP):
            self.stats["icmp_packets"] += 1
            self.handle_icmp(pkt, src, dst)

    # ================= STATISTICS DISPLAY =================
    def stats_loop(self):
        while True:
            time.sleep(STATS_INTERVAL)
            uptime = time.time() - self.stats["start_time"]
            pps = self.stats["total_packets"] / uptime if uptime > 0 else 0
            
            print(f"\n{C['info']}{'='*60}{C['rst']}")
            print(f"{C['info']}STATISTICS (Uptime: {uptime:.0f}s | PPS: {pps:.2f}){C['rst']}")
            print(f"  Total Packets: {self.stats['total_packets']}")
            print(f"  TCP: {self.stats['tcp_packets']} | UDP: {self.stats['udp_packets']} | ICMP: {self.stats['icmp_packets']} | ARP: {self.stats['arp_packets']}")
            print(f"  {C['high']}Alerts Generated: {self.stats['alerts']}{C['rst']}")
            print(f"  Active Trackers: {len(self.port_scan_tracker)} IPs")
            if self.target_ip:
                print(f"  {C['info']}Monitoring Traffic for: {self.target_ip}{C['rst']}")
            print(f"{C['info']}{'='*60}{C['rst']}\n")

    # ================= ACTIVE REDIRECTION (ARP SPOOFING) =================
    def spoof(self, target_ip, gateway_ip):
        """Perform ARP poisoning to redirect traffic through this NIDS"""
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        
        if not target_mac or not gateway_mac:
            print(f"{C['critical']}[!] Error: Could not resolve MAC for target or gateway. Ensure they are up.{C['rst']}")
            return False

        print(f"{C['info']}[*] Resolved MACs - Target: {target_mac} | Gateway: {gateway_mac}{C['rst']}")
        
        def spoof_loop():
            # Build the packets once (Layer 2)
            # 1. Tell target I am the gateway
            pkt_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            # 2. Tell gateway I am the target
            pkt_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
            
            while not self.stop_spoofing.is_set():
                from scapy.all import sendp
                sendp(pkt_target, verbose=False)
                sendp(pkt_gateway, verbose=False)
                time.sleep(2)

        threading.Thread(target=spoof_loop, daemon=True).start()
        return True

    def restore(self, target_ip, gateway_ip):
        """Restore original ARP settings (Unpoisoning)"""
        print(f"\n{C['info']}[*] Restoring network state (Unpoisoning)...{C['rst']}")
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        
        if target_mac and gateway_mac:
            from scapy.all import sendp
            # Send correct MACs back (broadcast to be sure)
            pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac)
            pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac)
            
            sendp(pkt1, count=7, verbose=False)
            sendp(pkt2, count=7, verbose=False)

    # ================= START ENGINE =================
    def run(self):
        print(f"\n{C['critical']}{'='*60}{C['rst']}")
        print(f"{C['critical']}ADVANCED NETWORK INTRUSION DETECTION SYSTEM{C['rst']}")
        print(f"{C['critical']}{'='*60}{C['rst']}")
        print(f"\n[*] Interface: {self.iface}")
        print(f"[*] Local IP: {self.local_ip}")
        print(f"[*] Mode: {'PROMISCUOUS (Network-Wide)' if self.promiscuous else 'HOST-BASED (This Machine Only)'}")
        print(f"[*] BPF Filter: {self.bpf}")
        print(f"[*] Dry Run: {self.dry_run}")
        if self.log_file:
            print(f"[*] Log File: {self.log_file}")
        print(f"\n[*] Detection Capabilities:")
        print(f"    - Port Scanning (SYN, FIN, XMAS, NULL)")
        print(f"    - SYN Flood Attacks")
        print(f"    - ARP Spoofing")
        print(f"    - Payload Analysis (SQLi, XSS, Path Traversal, etc.)")
        print(f"    - ICMP Floods")
        print(f"    - DNS Tunneling")
        print(f"    - Service Detection")
        if self.target_ip:
            print(f"    - Active Redirection: ON (Monitoring {self.target_ip})")
        print(f"\n{C['info']}[*] Monitoring started...{C['rst']}\n")

        # Start stats thread
        threading.Thread(target=self.stats_loop, daemon=True).start()

        try:
            sniff(
                iface=self.iface,
                filter=self.bpf,
                prn=self.handle_packet,
                store=False,
                promisc=self.promiscuous
            )
        except (KeyboardInterrupt, SystemExit):
            # Stop spoofing and restore network
            if nids.target_ip:
                nids.stop_spoofing.set()
                nids.restore(nids.target_ip, nids.gateway_ip)
                
            print(f"\n{C['info']}--- FINAL SUMMARY ---{C['rst']}")
            print(f"[*] Total alerts: {self.stats['alerts']}")
            print(f"[*] Total packets: {self.stats['total_packets']}\n")
            sys.exit(0)

# ================= MAIN =================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Host-based (monitor this machine only)
  sudo python3 nids_advanced.py --iface eth0
  
  # Network-wide (monitor all traffic on the network)
  sudo python3 nids_advanced.py --iface eth0 --promiscuous
  
  # With logging
  sudo python3 nids_advanced.py --iface eth0 --promiscuous --log alerts.json
  
  # Custom filter
  sudo python3 nids_advanced.py --iface wlan0 --bpf "tcp or arp or icmp"
        """
    )
    
    parser.add_argument("--iface", default=conf.iface, help="Network interface to monitor")
    parser.add_argument("--bpf", default="tcp or arp or udp or icmp", help="BPF filter string")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode (testing)")
    parser.add_argument("--log", dest="log_file", help="Log alerts to JSON file")
    parser.add_argument("--promiscuous", action="store_true", help="Enable promiscuous mode (monitor all network traffic)")
    parser.add_argument("--target-ip", help="IP of a specific machine to monitor (Active Redirection)")
    parser.add_argument("--gateway-ip", help="IP of the Router/Gateway (Required for --target-ip)")

    args = parser.parse_args()
    
    # Validation for Active Monitoring
    if args.target_ip and not args.gateway_ip:
        print(f"\n{Fore.RED}[!] Error: --gateway-ip is required when using --target-ip{Style.RESET_ALL}\n")
        sys.exit(1)

    # Must run as root/admin
    try:
        nids = AdvancedNIDS(args.iface, args.bpf, args.dry_run, args.log_file, args.promiscuous)
        
        # Start Active Redirection if requested
        if args.target_ip:
            nids.target_ip = args.target_ip
            nids.gateway_ip = args.gateway_ip
            if not nids.spoof(args.target_ip, args.gateway_ip):
                sys.exit(1)
        
        nids.run()
    except PermissionError:
        print(f"\n{Fore.RED}[!] Error: This script requires administrator/root privileges to sniff packets.{Style.RESET_ALL}")
        if os.name == 'nt':
            print("[*] Please run this terminal as Administrator.\n")
        else:
            print(f"[*] Run with: sudo python3 {__file__}\n")