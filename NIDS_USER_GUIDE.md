# Simple NIDS Guide
## In linux based system it is easy to use this ids system 
### Step 0: Virtual Machine Setup
Before starting, your Virtual Machine (Kali) must be configured to "talk" to the real world:
1.  **Bridged Mode:** In VM Settings -> Network, set Adapter to **Bridged**. This gives Kali its own IP address on your home WiFi.
2.  **Promiscuous Mode:** In VM Settings -> Network -> Advanced, set Promiscuous Mode to **"Allow All"**. This allows Kali to "hear" traffic meant for other machines.

---

### Step 1: Prepare the System (On Kali)
Run this command to keep the target's internet working during monitoring:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

---

### Step 2: Start the NIDS (On Kali)
Run the script and tell it who to watch:
```bash
sudo python3 nids_advanced.py --iface wlan0 --target-ip 192.168.0.181 --gateway-ip 192.168.0.1
```

---

### Step 5: Enable Active Blocking (IPS Mode)
To automatically block attackers for 60 seconds, add the `--ips` flag:
```bash
sudo python3 nids_advanced.py --iface wlan0 --ips
```
*   **Action:** When a threat is detected, the NIDS uses `iptables` to block the attacking IP.
*   **Protection:** Your Local IP and Gateway are automatically excluded from being blocked.
*   **Target IP:** The IP of the Windows machine.
*   **Gateway IP:** The IP of your Router.

---

### Step 3: Run the Test (On Windows)
On your Windows machine, run the tester to simulate an attack:
```powershell
python test_nids.py --target 192.168.0.1
```

---

### Step 4: Watch for Detections
Check your Kali screen for alerts. It will automatically detect:
*   **Port Scanning** (Finding open ports)
*   **SYN Flooding** (Crashing a service)
*   **Malicious Payloads** (Hackers sending bad commands)
*   **Active Blocking** (IPS mode - automatically dropping attacker packets)

---

### Common Fixes
*   **Target loses Internet:** Double-check Step 1.
*   **Zero Alerts:** Ensure Step 0 (Bridged Mode) is correctly set.
*   **Permission Denied:** Always type `sudo` before your commands on Kali.
