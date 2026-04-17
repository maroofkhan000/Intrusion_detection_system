# 🛡️ Advanced Network Intrusion Detection System (NIDS)

An advanced network security tool that monitors and detects various network attacks in real-time. This version includes **Active Redirection** to monitor other devices on the same network.

### ✨ Key Features
*   **Active Monitoring:** Uses ARP Redirection to monitor remote target devices.
*   **Attack Detection:** Identifies Port Scanning, SYN Flooding, ICMP Flooding, and ARP Spoofing.
*   **Payload Analysis:** Detects malicious patterns like SQL Injection and Command Injection.
*   **Cross-Platform Tester:** Includes a full testing suite to verify detections.

### 🚀 Getting Started
1.  **Read the Guide:** Check [NIDS_USER_GUIDE.md](./NIDS_USER_GUIDE.md) for detailed setup.
2.  **Enable Forwarding:** `sudo sysctl -w net.ipv4.ip_forward=1`
3.  **Run:** `sudo python3 nids_advanced.py --iface wlan0 --target-ip <IP> --gateway-ip <IP>`

---
*Created for CodeAlpha Internship - Task 2*
