"""
Quick Test - Simple packet generator for quick testing
Generates 20 packets (15 malicious, 5 benign) quickly
"""

from scapy.all import *
import random
import time

def quick_test():
    print("\n" + "="*50)
    print("Quick Malware Detection Test")
    print("="*50)
    print("\nGenerating 20 packets (15 malicious, 5 benign)...")
    print("Starting in 2 seconds...\n")
    time.sleep(2)
    
    # Simple IPs
    attacker = "192.168.1.100"
    target = "192.168.1.1"
    
    count = 0
    
    # Generate 15 malicious packets
    print("Sending malicious packets...")
    for i in range(15):
        # Port scan
        packet = IP(src=attacker, dst=target)/TCP(sport=random.randint(1024, 65535), dport=random.randint(1, 1024), flags='S')
        send(packet, verbose=False)
        count += 1
        print(f"  [{count}/20] Malicious packet sent (Port Scan)")
        time.sleep(0.05)
    
    # Generate 5 benign packets
    print("\nSending benign packets...")
    for i in range(5):
        # Normal HTTP
        packet = IP(src=attacker, dst=target)/TCP(sport=random.randint(49152, 65535), dport=80, flags='S')
        send(packet, verbose=False)
        count += 1
        print(f"  [{count}/20] Benign packet sent (HTTP)")
        time.sleep(0.05)
    
    print("\n" + "="*50)
    print(f"✓ Done! Sent {count} packets")
    print("  - 15 Malicious (Port Scans)")
    print("  - 5 Benign (HTTP)")
    print("="*50)
    print("\nCheck your Dashboard for the captured packets!\n")

if __name__ == "__main__":
    try:
        # Check privileges
        test = IP(dst="127.0.0.1")/ICMP()
        quick_test()
    except PermissionError:
        print("\n" + "="*50)
        print("ERROR: Need Administrator/Root privileges!")
        print("="*50)
        print("\nRun as:")
        print("  Windows: Run PowerShell as Administrator")
        print("  Linux/Mac: sudo python3 quick_test.py")
        print("="*50 + "\n")
