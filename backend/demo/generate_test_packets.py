"""
Demo Packet Generator for Testing Malware Detection
Generates both benign and malicious network packets for testing purposes.
Malicious packets are generated more frequently (70% malicious, 30% benign).
"""

from scapy.all import *
import random
import time
from datetime import datetime

# Configuration
TOTAL_PACKETS = 50  # Total number of packets to generate
MALICIOUS_RATIO = 0.7  # 70% malicious packets
INTERFACE = None  # None = default interface, or specify like "Wi-Fi"
DELAY_BETWEEN_PACKETS = 0.1  # seconds

# IP addresses for simulation
ATTACKER_IPS = [
    "192.168.1.100",
    "192.168.1.101", 
    "192.168.1.102",
    "10.0.0.50",
    "172.16.0.100"
]

TARGET_IPS = [
    "192.168.1.1",
    "192.168.1.10",
    "8.8.8.8",
    "1.1.1.1",
    "192.168.1.254"
]

BENIGN_PORTS = [80, 443, 53, 22, 21, 25, 110, 143]
MALICIOUS_PORTS = [1234, 4444, 5555, 6666, 31337, 12345, 54321]

def generate_benign_packet():
    """Generate a benign network packet (normal traffic)"""
    src_ip = random.choice(ATTACKER_IPS)
    dst_ip = random.choice(TARGET_IPS)
    src_port = random.randint(49152, 65535)  # Ephemeral port
    dst_port = random.choice(BENIGN_PORTS)
    
    # Random benign packet types
    packet_type = random.choice(['http', 'dns', 'https', 'ssh'])
    
    if packet_type == 'http':
        # HTTP GET request
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=80, flags='PA')/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    elif packet_type == 'dns':
        # DNS query
        packet = IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=53)/DNS(rd=1, qd=DNSQR(qname="www.google.com"))
    elif packet_type == 'https':
        # HTTPS (TLS handshake)
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=443, flags='S')
    else:  # ssh
        # SSH connection
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=22, flags='S')
    
    return packet

def generate_malicious_packet():
    """Generate a malicious network packet (attack simulation)"""
    src_ip = random.choice(ATTACKER_IPS)
    dst_ip = random.choice(TARGET_IPS)
    
    # Random malicious attack types
    attack_type = random.choice(['port_scan', 'ddos', 'sql_injection', 'xss', 'brute_force', 'backdoor'])
    
    if attack_type == 'port_scan':
        # Port scanning - SYN scan
        dst_port = random.randint(1, 65535)
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='S')
        
    elif attack_type == 'ddos':
        # DDoS - SYN flood
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags='S')
        
    elif attack_type == 'sql_injection':
        # SQL Injection attempt
        payload = "' OR '1'='1'; DROP TABLE users; --"
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags='PA')/Raw(load=f"GET /login?user={payload} HTTP/1.1\r\n\r\n")
        
    elif attack_type == 'xss':
        # XSS attack attempt
        payload = "<script>alert('XSS')</script>"
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags='PA')/Raw(load=f"GET /search?q={payload} HTTP/1.1\r\n\r\n")
        
    elif attack_type == 'brute_force':
        # Brute force login attempt
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=22, flags='PA')/Raw(load="admin:password123")
        
    else:  # backdoor
        # Backdoor communication
        dst_port = random.choice(MALICIOUS_PORTS)
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=dst_port, flags='PA')/Raw(load="BACKDOOR_COMMAND")
    
    return packet

def main():
    print("=" * 60)
    print("Demo Packet Generator for Malware Detection Testing")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  Total Packets: {TOTAL_PACKETS}")
    print(f"  Malicious Ratio: {int(MALICIOUS_RATIO * 100)}%")
    print(f"  Benign Ratio: {int((1 - MALICIOUS_RATIO) * 100)}%")
    print(f"  Delay: {DELAY_BETWEEN_PACKETS}s between packets")
    print(f"  Interface: {INTERFACE or 'Default'}")
    print("\n" + "=" * 60)
    
    # Calculate packet counts
    malicious_count = int(TOTAL_PACKETS * MALICIOUS_RATIO)
    benign_count = TOTAL_PACKETS - malicious_count
    
    print(f"\nGenerating {malicious_count} malicious and {benign_count} benign packets...")
    print("\nStarting packet generation in 3 seconds...")
    print("Make sure your packet capture is running!\n")
    time.sleep(3)
    
    packets_sent = 0
    malicious_sent = 0
    benign_sent = 0
    
    try:
        for i in range(TOTAL_PACKETS):
            # Randomly decide if this packet should be malicious or benign
            if random.random() < MALICIOUS_RATIO:
                packet = generate_malicious_packet()
                packet_type = "MALICIOUS"
                malicious_sent += 1
            else:
                packet = generate_benign_packet()
                packet_type = "BENIGN"
                benign_sent += 1
            
            # Send the packet
            try:
                send(packet, verbose=False, iface=INTERFACE)
                packets_sent += 1
                
                # Print progress
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                print(f"[{timestamp}] Packet {packets_sent}/{TOTAL_PACKETS} - {packet_type:10} | "
                      f"{packet[IP].src:15} -> {packet[IP].dst:15} | "
                      f"Proto: {packet.sprintf('%IP.proto%'):5}")
                
                # Delay between packets
                time.sleep(DELAY_BETWEEN_PACKETS)
                
            except Exception as e:
                print(f"Error sending packet {i+1}: {e}")
                continue
    
    except KeyboardInterrupt:
        print("\n\nPacket generation interrupted by user!")
    
    print("\n" + "=" * 60)
    print("Packet Generation Summary")
    print("=" * 60)
    print(f"Total Packets Sent: {packets_sent}")
    print(f"Malicious Packets: {malicious_sent} ({malicious_sent/packets_sent*100:.1f}%)")
    print(f"Benign Packets: {benign_sent} ({benign_sent/packets_sent*100:.1f}%)")
    print("=" * 60)
    print("\nDone! Check your packet capture interface for the generated packets.")

if __name__ == "__main__":
    # Check if running with admin/root privileges
    try:
        # Test if we can create raw sockets
        test_packet = IP(dst="127.0.0.1")/ICMP()
        print("✓ Running with sufficient privileges\n")
    except Exception as e:
        print("=" * 60)
        print("ERROR: Insufficient Privileges")
        print("=" * 60)
        print("\nThis script requires administrator/root privileges to send packets.")
        print("\nPlease run as:")
        print("  Windows: Run PowerShell/CMD as Administrator")
        print("  Linux/Mac: sudo python generate_test_packets.py")
        print("=" * 60)
        exit(1)
    
    main()
