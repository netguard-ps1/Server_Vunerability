from scapy.all import sniff, wrpcap, get_if_list, conf
from datetime import datetime
import threading
import os
import platform
import subprocess
import re
from collections import defaultdict

class PacketCapture:
    def __init__(self, socketio, capture_dir):
        self.socketio = socketio
        self.capture_dir = capture_dir
        self.is_capturing = False
        self.capture_thread = None
        self.packets = []
        self.packet_count = 0
        self.current_interface = None
        self.first_packet_time = None  # Track first packet time for delta
        self.last_packet_time = None   # Track last packet time for delta
        self.clients_data = defaultdict(lambda: {
            'ip': '',
            'mac': '',
            'protocols': set(),
            'packet_count': 0,
            'last_activity': None,
            'active': True,
            'benign_count': 0,
            'malicious_count': 0
        })
        self.ip_only = False
        
    def get_interfaces(self):
        """Get list of available network interfaces using PowerShell (like MyShark)"""
        try:
            interfaces_list = []
            
            # For Windows, use PowerShell to get interface details
            if platform.system() == 'Windows':
                try:
                    result = subprocess.check_output(
                        ["powershell", "-Command", 
                         "Get-NetAdapter | Format-List Name, InterfaceDescription, InterfaceGuid"],
                        universal_newlines=True
                    )
                    
                    blocks = result.strip().split("\n\n")
                    for block in blocks:
                        name_match = re.search(r"Name\s*:\s*(.*)", block)
                        desc_match = re.search(r"InterfaceDescription\s*:\s*(.*)", block)
                        guid_match = re.search(r"InterfaceGuid\s*:\s*{(.*)}", block)
                        
                        if name_match and guid_match:
                            name = name_match.group(1).strip()
                            desc = desc_match.group(1).strip() if desc_match else ""
                            guid = guid_match.group(1).strip()
                            
                            interfaces_list.append({
                                "name": name,
                                "description": desc,
                                "guid": guid
                            })
                except Exception as e:
                    print(f"PowerShell interface detection failed: {e}, using fallback")
                    # Fallback to Scapy's basic list
                    interfaces = get_if_list()
                    interfaces_list = [{'name': iface, 'description': iface, 'guid': iface} for iface in interfaces]
            else:
                # For Linux/Mac
                interfaces = get_if_list()
                interfaces_list = [{'name': iface, 'description': iface, 'guid': iface} for iface in interfaces]
            
            return {
                'success': True,
                'interfaces': interfaces_list,
                'default': interfaces_list[0]['name'] if interfaces_list else None
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_packet(self, pkt):
        """Process captured packet and extract information"""
        try:
            # If IP-only capture is enabled, ignore non-IP packets
            if self.ip_only and not pkt.haslayer('IP'):
                return
            # Get packet timestamp
            packet_time = float(pkt.time) if hasattr(pkt, 'time') else datetime.now().timestamp()
            
            # Calculate delta time
            if self.first_packet_time is None:
                self.first_packet_time = packet_time
                delta_time = 0.0
            else:
                delta_time = packet_time - (self.last_packet_time or self.first_packet_time)
            
            self.last_packet_time = packet_time
            
            # Format timestamp as yyyy/mm/dd hh:mm:ss
            dt = datetime.fromtimestamp(packet_time)
            formatted_time = dt.strftime('%Y/%m/%d %H:%M:%S')
            
            packet_info = {
                'no': self.packet_count + 1,
                'timestamp': formatted_time,
                'delta_time': round(delta_time, 6),  # Delta in seconds
                'src_ip': '',
                'dst_ip': '',
                'src_mac': '',
                'dst_mac': '',
                'protocol': '',
                'length': len(pkt),
                'info': pkt.summary(),
                'raw': bytes(pkt).hex(),
                'class': 'benign'
            }
            
            # Extract Ethernet layer info
            if pkt.haslayer('Ether'):
                packet_info['src_mac'] = pkt['Ether'].src
                packet_info['dst_mac'] = pkt['Ether'].dst
            
            # Extract IP layer info
            if pkt.haslayer('IP'):
                packet_info['src_ip'] = pkt['IP'].src
                packet_info['dst_ip'] = pkt['IP'].dst
            
            # Handle ARP packets
            if pkt.haslayer('ARP'):
                packet_info['src_ip'] = pkt['ARP'].psrc
                packet_info['dst_ip'] = pkt['ARP'].pdst
            
            # Detect protocol for all packets (IP and non-IP)
            packet_info['protocol'] = self._detect_protocol(pkt)
            
            # Update client data
            if packet_info['src_ip'] and packet_info['src_mac']:
                client_key = f"{packet_info['src_ip']}_{packet_info['src_mac']}"
                self.clients_data[client_key]['ip'] = packet_info['src_ip']
                self.clients_data[client_key]['mac'] = packet_info['src_mac']
                self.clients_data[client_key]['protocols'].add(packet_info['protocol'])
                self.clients_data[client_key]['packet_count'] += 1
                self.clients_data[client_key]['last_activity'] = packet_info['timestamp']
                self.clients_data[client_key]['active'] = True
                
                # Track classification stats
                if packet_info['class'] == 'malicious':
                    self.clients_data[client_key]['malicious_count'] += 1
                else:
                    self.clients_data[client_key]['benign_count'] += 1
            
            self.packets.append(pkt)
            self.packet_count += 1
            
            # Emit packet to frontend via WebSocket
            self.socketio.emit('new_packet', packet_info)
            
            # Emit updated clients data
            clients_list = []
            for key, data in self.clients_data.items():
                clients_list.append({
                    'ip': data['ip'],
                    'mac': data['mac'],
                    'protocols': list(data['protocols']),
                    'packet_count': data['packet_count'],
                    'last_activity': data['last_activity'],
                    'active': data['active'],
                    'benign_count': data['benign_count'],
                    'malicious_count': data['malicious_count']
                })
            self.socketio.emit('clients_update', clients_list)
            
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_capture(self, interface, ip_only=False):
        """Start packet capture on specified interface - NO ADMIN REQUIRED"""
        if self.is_capturing:
            return {'success': False, 'error': 'Capture already in progress'}
        
        try:
            self.current_interface = interface
            self.is_capturing = True
            self.packets = []
            self.packet_count = 0
            self.first_packet_time = None  # Reset delta time tracking
            self.last_packet_time = None
            self.clients_data.clear()
            self.ip_only = bool(ip_only)
            
            def capture_thread():
                try:
                    # Use promisc=False to avoid requiring admin privileges
                    # This captures packets sent to/from this machine only
                    sniff(
                        iface=interface,
                        prn=self.process_packet,
                        store=False,
                        promisc=False,  # No promiscuous mode = no admin required
                        stop_filter=lambda x: not self.is_capturing
                    )
                except PermissionError:
                    print(f"Permission error - trying without interface specification...")
                    # Fallback: capture on all interfaces without specifying one
                    try:
                        sniff(
                            prn=self.process_packet,
                            store=False,
                            promisc=False,
                            stop_filter=lambda x: not self.is_capturing
                        )
                    except Exception as e2:
                        print(f"Fallback capture error: {e2}")
                        self.is_capturing = False
                except Exception as e:
                    print(f"Capture error: {e}")
                    self.is_capturing = False
            
            self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
            self.capture_thread.start()
            
            return {
                'success': True,
                'message': f'Capture started on {interface} (non-promiscuous mode)',
                'interface': interface
            }
        except Exception as e:
            self.is_capturing = False
            return {'success': False, 'error': str(e)}
    
    def stop_capture(self):
        """Stop packet capture"""
        if not self.is_capturing:
            return {'success': False, 'error': 'No capture in progress'}
        
        self.is_capturing = False
        
        # Save captured packets to PCAP file
        if self.packets:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"capture_{timestamp}.pcap"
            filepath = os.path.join(self.capture_dir, filename)
            
            try:
                wrpcap(filepath, self.packets)
                return {
                    'success': True,
                    'message': 'Capture stopped',
                    'packet_count': self.packet_count,
                    'filename': filename
                }
            except Exception as e:
                return {
                    'success': True,
                    'message': 'Capture stopped but failed to save PCAP',
                    'packet_count': self.packet_count,
                    'error': str(e)
                }
        
        return {
            'success': True,
            'message': 'Capture stopped',
            'packet_count': self.packet_count
        }
    
    def get_status(self):
        """Get current capture status"""
        return {
            'is_capturing': self.is_capturing,
            'interface': self.current_interface,
            'packet_count': self.packet_count,
            'clients_count': len(self.clients_data)
        }
    
    def add_client_packet(self, packet_data):
        """Add packet from remote client agent"""
        try:
            # Create packet info from client data
            packet_info = {
                'no': self.packet_count + 1,
                'timestamp': packet_data.get('timestamp', datetime.now().isoformat()),
                'src_ip': packet_data.get('src_ip', ''),
                'dst_ip': packet_data.get('dst_ip', ''),
                'src_mac': packet_data.get('src_mac', ''),
                'dst_mac': packet_data.get('dst_mac', ''),
                'protocol': packet_data.get('protocol', ''),
                'length': packet_data.get('length', 0),
                'info': packet_data.get('info', ''),
                'raw': packet_data.get('raw', ''),
                'client_name': packet_data.get('client_name', 'Unknown')
            }
            
            self.packet_count += 1
            
            # Update client data
            if packet_info['src_ip'] and packet_info['src_mac']:
                client_key = f"{packet_info['src_ip']}_{packet_info['src_mac']}"
                self.clients_data[client_key]['ip'] = packet_info['src_ip']
                self.clients_data[client_key]['mac'] = packet_info['src_mac']
                self.clients_data[client_key]['protocols'].add(packet_info['protocol'])
                self.clients_data[client_key]['packet_count'] += 1
                self.clients_data[client_key]['last_activity'] = packet_info['timestamp']
                self.clients_data[client_key]['active'] = True
            
            # Emit packet to frontend
            self.socketio.emit('new_packet', packet_info)
            
            # Emit updated clients data
            clients_list = []
            for key, data in self.clients_data.items():
                clients_list.append({
                    'ip': data['ip'],
                    'mac': data['mac'],
                    'protocols': list(data['protocols']),
                    'packet_count': data['packet_count'],
                    'last_activity': data['last_activity'],
                    'active': data['active']
                })
            self.socketio.emit('clients_update', clients_list)
            
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _detect_protocol(self, pkt):
        """Detect protocol - shows application layer when available, transport layer otherwise"""
        try:
            # Check for ICMPv6 first (before other checks)
            if pkt.haslayer('ICMPv6'):
                return 'ICMPv6'
            
            # Check for application layer protocols
            if pkt.haslayer('DNS'):
                return 'DNS'
            
            # UDP-based protocols
            if pkt.haslayer('UDP'):
                udp_layer = pkt['UDP']
                sport = udp_layer.sport
                dport = udp_layer.dport
                
                if sport in [67, 68] or dport in [67, 68]:
                    return 'DHCP'
                elif sport == 5353 or dport == 5353:
                    return 'mDNS'
                elif sport == 53 or dport == 53:
                    return 'DNS'
                elif sport == 123 or dport == 123:
                    return 'NTP'
                elif sport == 161 or dport == 161:
                    return 'SNMP'
                elif sport == 514 or dport == 514:
                    return 'Syslog'
                elif sport == 1900 or dport == 1900:
                    return 'SSDP'
                else:
                    return 'UDP'
            
            # TCP-based protocols
            if pkt.haslayer('TCP'):
                tcp_layer = pkt['TCP']
                sport = tcp_layer.sport
                dport = tcp_layer.dport
                
                # Web protocols - only detect if there's actual HTTP content
                if (sport == 80 or dport == 80) and pkt.haslayer('Raw'):
                    try:
                        payload = bytes(pkt['Raw'].load).decode('utf-8', errors='ignore')
                        if any(method in payload for method in ['GET ', 'POST ', 'HTTP/', 'HEAD ', 'PUT ', 'DELETE ']):
                            return 'HTTP'
                    except:
                        pass
                elif (sport == 8080 or dport == 8080) and pkt.haslayer('Raw'):
                    try:
                        payload = bytes(pkt['Raw'].load).decode('utf-8', errors='ignore')
                        if any(method in payload for method in ['GET ', 'POST ', 'HTTP/', 'HEAD ', 'PUT ', 'DELETE ']):
                            return 'HTTP'
                    except:
                        pass
                
                # Database protocols
                elif sport == 3306 or dport == 3306:
                    return 'MySQL'
                elif sport == 5432 or dport == 5432:
                    return 'PostgreSQL'
                elif sport == 1433 or dport == 1433:
                    return 'MSSQL'
                elif sport == 27017 or dport == 27017:
                    return 'MongoDB'
                elif sport == 6379 or dport == 6379:
                    return 'Redis'
                
                # File transfer
                elif sport == 21 or dport == 21:
                    return 'FTP'
                elif sport == 22 or dport == 22:
                    return 'SSH'
                elif sport == 23 or dport == 23:
                    return 'Telnet'
                elif sport == 445 or dport == 445:
                    return 'SMB'
                
                # Email protocols
                elif sport == 25 or dport == 25:
                    return 'SMTP'
                elif sport == 110 or dport == 110:
                    return 'POP3'
                elif sport == 143 or dport == 143:
                    return 'IMAP'
                elif sport == 587 or dport == 587:
                    return 'SMTP'
                elif sport == 993 or dport == 993:
                    return 'IMAPS'
                elif sport == 995 or dport == 995:
                    return 'POP3S'
                
                # Other protocols
                elif sport == 389 or dport == 389:
                    return 'LDAP'
                elif sport == 636 or dport == 636:
                    return 'LDAPS'
                elif sport == 3389 or dport == 3389:
                    return 'RDP'
                elif sport == 5900 or dport == 5900:
                    return 'VNC'
                else:
                    return 'TCP'
            
            # Other protocols
            if pkt.haslayer('ICMP'):
                return 'ICMP'
            elif pkt.haslayer('IGMP'):
                return 'IGMP'
            elif pkt.haslayer('ARP'):
                return 'ARP'
            elif pkt.haslayer('Ether'):
                # Check Ethernet type for other protocols
                ether = pkt['Ether']
                if ether.type == 0x0800:  # IPv4
                    return 'IP'
                elif ether.type == 0x0806:  # ARP
                    return 'ARP'
                elif ether.type == 0x86DD:  # IPv6
                    # For IPv6, check if there's TCP/UDP inside
                    if pkt.haslayer('TCP'):
                        return 'TCP'
                    elif pkt.haslayer('UDP'):
                        return 'UDP'
                    else:
                        return 'IPv6'
                elif ether.type == 0x8100:  # 802.1Q VLAN
                    return 'VLAN'
                elif ether.type == 0x88CC:  # LLDP
                    return 'LLDP'
                elif ether.type == 0x8863 or ether.type == 0x8864:  # PPPoE
                    return 'PPPoE'
                else:
                    return 'Ethernet'
            else:
                return 'Unknown'
                
        except Exception as e:
            return 'Unknown'
