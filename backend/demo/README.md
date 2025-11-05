# Demo Packet Generator

This folder contains a demo packet generator for testing the malware detection functionality of the Server Vulnerability application.

## Files

- `generate_test_packets.py` - Main packet generator script

## Requirements

```bash
pip install scapy
```

## Usage

### Step 1: Start Your Packet Capture
First, start the packet capture in your main application:
1. Open the Dashboard
2. Select your network interface
3. Click "Start Capture"

### Step 2: Run the Packet Generator

**Windows (Run as Administrator):**
```powershell
# Open PowerShell as Administrator
cd backend/demo
python generate_test_packets.py
```

**Linux/Mac:**
```bash
sudo python3 generate_test_packets.py
```

### Step 3: Watch the Results
- The script will generate 50 packets (70% malicious, 30% benign)
- You'll see real-time output showing each packet sent
- Check your Dashboard to see the packets being captured
- Malicious packets should be highlighted in red
- The malware count indicator should update

## Configuration

You can modify these settings in `generate_test_packets.py`:

```python
TOTAL_PACKETS = 50              # Total number of packets
MALICIOUS_RATIO = 0.7           # 70% malicious
DELAY_BETWEEN_PACKETS = 0.1     # Delay in seconds
INTERFACE = None                # Network interface (None = default)
```

## Attack Types Generated

### Malicious Packets (70%):
1. **Port Scan** - SYN scanning on random ports
2. **DDoS** - SYN flood attacks
3. **SQL Injection** - SQL injection payloads in HTTP requests
4. **XSS** - Cross-site scripting attempts
5. **Brute Force** - SSH login attempts
6. **Backdoor** - Communication on suspicious ports

### Benign Packets (30%):
1. **HTTP** - Normal web requests
2. **DNS** - Domain name queries
3. **HTTPS** - Secure web connections
4. **SSH** - Legitimate SSH connections

## Example Output

```
============================================================
Demo Packet Generator for Malware Detection Testing
============================================================

Configuration:
  Total Packets: 50
  Malicious Ratio: 70%
  Benign Ratio: 30%
  Delay: 0.1s between packets
  Interface: Default

============================================================

Generating 35 malicious and 15 benign packets...

Starting packet generation in 3 seconds...
Make sure your packet capture is running!

[21:15:30.123] Packet 1/50 - MALICIOUS  | 192.168.1.100   -> 192.168.1.1     | Proto: tcp
[21:15:30.234] Packet 2/50 - BENIGN     | 192.168.1.101   -> 8.8.8.8         | Proto: udp
[21:15:30.345] Packet 3/50 - MALICIOUS  | 192.168.1.102   -> 192.168.1.10    | Proto: tcp
...

============================================================
Packet Generation Summary
============================================================
Total Packets Sent: 50
Malicious Packets: 35 (70.0%)
Benign Packets: 15 (30.0%)
============================================================

Done! Check your packet capture interface for the generated packets.
```

## Troubleshooting

### "Insufficient Privileges" Error
- **Windows**: Right-click PowerShell/CMD and select "Run as Administrator"
- **Linux/Mac**: Use `sudo` before the command

### Packets Not Appearing in Dashboard
1. Make sure packet capture is running
2. Check that you're capturing on the correct network interface
3. Verify the "Show only IP packets" filter is enabled
4. Check if your firewall is blocking the packets

### Import Error: No module named 'scapy'
```bash
pip install scapy
```

## Notes

- This is for **TESTING PURPOSES ONLY**
- Do not run this on production networks
- The packets are sent to real IP addresses but are crafted for testing
- Some antivirus software may flag this script - it's a false positive for testing tools
- The malware detection model should classify most malicious packets correctly

## Safety

This script:
- ✓ Only generates test packets locally
- ✓ Does not perform actual attacks
- ✓ Uses simulated payloads
- ✓ Can be safely run in a controlled environment
- ✗ Should NOT be used on networks you don't own/control
