from scapy.all import rdpcap, wrpcap, PcapNgReader
from collections import Counter
from datetime import datetime
import os

class PcapAnalyzer:
    def __init__(self, capture_dir):
        self.capture_dir = capture_dir
    
    def analyze_pcap(self, filepath):
        """Analyze a PCAP/PCAPNG file and return statistics"""
        try:
            # Support both pcap and pcapng files
            if filepath.endswith('.pcapng'):
                packets = list(PcapNgReader(filepath))
            else:
                packets = rdpcap(filepath)
            
            analysis = {
                'total_packets': len(packets),
                'protocols': {},
                'top_sources': {},
                'top_destinations': {},
                'packets_data': [],
                'timeline': []
            }
            
            protocol_counter = Counter()
            src_ip_counter = Counter()
            dst_ip_counter = Counter()
            
            # Track previous packet time for delta calculation
            prev_time = None
            
            for idx, pkt in enumerate(packets):
                current_time = float(pkt.time)
                delta_time = 0.0 if prev_time is None else current_time - prev_time
                prev_time = current_time
                
                packet_info = {
                    'no': idx + 1,
                    'timestamp': datetime.fromtimestamp(current_time).isoformat(),
                    'delta_time': round(delta_time, 6),  # Delta time in seconds
                    'src_ip': '',
                    'dst_ip': '',
                    'src_mac': '',
                    'dst_mac': '',
                    'protocol': '',
                    'length': len(pkt),
                    'info': pkt.summary(),
                    'raw': bytes(pkt).hex(),
                    'class': 'benign'  # Default classification
                }
                
                # Extract Ethernet layer
                if pkt.haslayer('Ether'):
                    packet_info['src_mac'] = pkt['Ether'].src
                    packet_info['dst_mac'] = pkt['Ether'].dst
                
                # Extract IP layer
                if pkt.haslayer('IP'):
                    packet_info['src_ip'] = pkt['IP'].src
                    packet_info['dst_ip'] = pkt['IP'].dst
                    src_ip_counter[packet_info['src_ip']] += 1
                    dst_ip_counter[packet_info['dst_ip']] += 1
                
                # Handle ARP packets
                if pkt.haslayer('ARP'):
                    packet_info['src_ip'] = pkt['ARP'].psrc
                    packet_info['dst_ip'] = pkt['ARP'].pdst
                
                # Detect protocol for all packets (IP and non-IP)
                protocol = self._detect_protocol(pkt)
                packet_info['protocol'] = protocol
                protocol_counter[protocol] += 1
                
                analysis['packets_data'].append(packet_info)
                
                # Timeline data (group by minute)
                timestamp = datetime.fromtimestamp(float(pkt.time))
                time_key = timestamp.strftime('%Y-%m-%d %H:%M')
                
                # Find or create timeline entry
                timeline_entry = next((t for t in analysis['timeline'] if t['time'] == time_key), None)
                if timeline_entry:
                    timeline_entry['count'] += 1
                else:
                    analysis['timeline'].append({'time': time_key, 'count': 1})
            
            # Convert counters to dictionaries
            analysis['protocols'] = dict(protocol_counter.most_common())
            analysis['top_sources'] = dict(src_ip_counter.most_common(10))
            analysis['top_destinations'] = dict(dst_ip_counter.most_common(10))
            
            return {
                'success': True,
                'analysis': analysis
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
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
    
    def save_filtered_pcap(self, packets_data, filename):
        """Save filtered packets to a new PCAP file"""
        try:
            # This would require reconstructing packets from hex data
            # For now, return success with a note
            return {
                'success': True,
                'message': 'Filtered PCAP save not yet implemented',
                'filename': filename
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_pcap_list(self):
        """Get list of all PCAP files in capture directory"""
        try:
            pcap_files = []
            for filename in os.listdir(self.capture_dir):
                if filename.endswith(('.pcap', '.cap', '.pcapng')):
                    filepath = os.path.join(self.capture_dir, filename)
                    stat = os.stat(filepath)
                    pcap_files.append({
                        'filename': filename,
                        'size': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
            
            return {
                'success': True,
                'files': sorted(pcap_files, key=lambda x: x['modified'], reverse=True)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
