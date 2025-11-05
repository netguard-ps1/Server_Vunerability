"""
Client-Server Communication Handler
Manages client connections, file transfers, and communication
"""

import socket
import threading
import json
import os
import time
from datetime import datetime
import hashlib
from scapy.all import ARP, Ether, srp

class ClientServerManager:
    def __init__(self, host='0.0.0.0', port=9999, socketio=None):
        self.host = host
        self.port = port
        self.socketio = socketio
        self.server_socket = None
        self.running = False
        self.clients = {}  # {client_id: {socket, address, info}}
        self.file_storage = os.path.join(os.path.dirname(__file__), 'file_storage')
        self.transfer_chunk_size = 4096
        
        # Create file storage directory
        os.makedirs(self.file_storage, exist_ok=True)
    
    def _get_mac_address(self, ip):
        """Get MAC address for an IP using ARP"""
        try:
            # Create ARP request
            arp = ARP(pdst=ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and get response
            result = srp(packet, timeout=2, verbose=False)[0]
            
            if result:
                return result[0][1].hwsrc
            return None
        except Exception as e:
            print(f"[Server] Error getting MAC for {ip}: {e}")
            return None
        
    def start_server(self):
        """Start the client-server socket"""
        if self.running:
            return {'success': False, 'error': 'Server already running'}
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            # Start accepting clients in a separate thread
            accept_thread = threading.Thread(target=self._accept_clients, daemon=True)
            accept_thread.start()
            
            print(f"[Server] Started on {self.host}:{self.port}")
            return {'success': True, 'message': f'Server started on port {self.port}'}
            
        except Exception as e:
            print(f"[Server] Failed to start: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop_server(self):
        """Stop the client-server socket"""
        if not self.running:
            return {'success': False, 'error': 'Server not running'}
        
        try:
            self.running = False
            
            # Disconnect all clients
            for client_id in list(self.clients.keys()):
                self._disconnect_client(client_id)
            
            # Close server socket
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            
            print("[Server] Stopped")
            return {'success': True, 'message': 'Server stopped'}
            
        except Exception as e:
            print(f"[Server] Failed to stop: {e}")
            return {'success': False, 'error': str(e)}
    
    def _accept_clients(self):
        """Accept incoming client connections"""
        print("[Server] Accepting client connections...")
        
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, address = self.server_socket.accept()
                
                # Generate client ID
                client_id = f"{address[0]}:{address[1]}"
                
                print(f"[Server] Client connected: {client_id}")
                
                # Get MAC address
                mac_address = self._get_mac_address(address[0])
                
                # Store client info
                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': address,
                    'ip': address[0],
                    'port': address[1],
                    'mac': mac_address,
                    'connected_at': datetime.now().isoformat(),
                    'active': True
                }
                
                # Start client handler thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_id,),
                    daemon=True
                )
                client_thread.start()
                
                # Notify frontend via SocketIO
                if self.socketio:
                    self.socketio.emit('client_connected', {
                        'client_id': client_id,
                        'ip': address[0],
                        'port': address[1],
                        'mac': mac_address,
                        'timestamp': datetime.now().isoformat()
                    })
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[Server] Error accepting client: {e}")
                break
    
    def _handle_client(self, client_id):
        """Handle communication with a specific client"""
        client = self.clients.get(client_id)
        if not client:
            return
        
        client_socket = client['socket']
        
        try:
            while self.running and client['active']:
                # Receive data from client
                data = client_socket.recv(4096)
                
                if not data:
                    break
                
                # Parse message
                try:
                    message = json.loads(data.decode('utf-8'))
                    self._process_client_message(client_id, message)
                except json.JSONDecodeError:
                    print(f"[Server] Invalid JSON from {client_id}")
                
        except Exception as e:
            print(f"[Server] Error handling client {client_id}: {e}")
        finally:
            self._disconnect_client(client_id)
    
    def _process_client_message(self, client_id, message):
        """Process messages from clients"""
        msg_type = message.get('type')
        
        if msg_type == 'hello':
            # Client introduction
            self._send_to_client(client_id, {
                'type': 'welcome',
                'message': 'Connected to server',
                'server_time': datetime.now().isoformat()
            })
            
        elif msg_type == 'file_list_request':
            # Client requesting list of available files
            files = self._get_available_files()
            self._send_to_client(client_id, {
                'type': 'file_list',
                'files': files
            })
            
        elif msg_type == 'file_download_request':
            # Client wants to download a file
            filename = message.get('filename')
            self._send_file_to_client(client_id, filename)
            
        elif msg_type == 'file_upload_start':
            # Client wants to upload a file
            filename = message.get('filename')
            filesize = message.get('filesize')
            self._receive_file_from_client(client_id, filename, filesize)
            
        elif msg_type == 'ping':
            # Keep-alive ping
            self._send_to_client(client_id, {'type': 'pong'})
    
    def _send_to_client(self, client_id, message):
        """Send message to a specific client"""
        client = self.clients.get(client_id)
        if not client or not client['active']:
            return False
        
        try:
            data = json.dumps(message).encode('utf-8')
            client['socket'].sendall(data)
            return True
        except Exception as e:
            print(f"[Server] Error sending to {client_id}: {e}")
            return False
    
    def _disconnect_client(self, client_id):
        """Disconnect a client"""
        client = self.clients.get(client_id)
        if not client:
            return
        
        try:
            client['active'] = False
            client['socket'].close()
            del self.clients[client_id]
            
            print(f"[Server] Client disconnected: {client_id}")
            
            # Notify frontend
            if self.socketio:
                self.socketio.emit('client_disconnected', {
                    'client_id': client_id,
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            print(f"[Server] Error disconnecting {client_id}: {e}")
    
    def disconnect_client(self, client_id):
        """Manually disconnect a client (called from API)"""
        if client_id in self.clients:
            self._send_to_client(client_id, {
                'type': 'disconnect',
                'reason': 'Disconnected by server'
            })
            time.sleep(0.5)  # Give time for message to send
            self._disconnect_client(client_id)
            return {'success': True, 'message': f'Client {client_id} disconnected'}
        return {'success': False, 'error': 'Client not found'}
    
    def get_connected_clients(self):
        """Get list of connected clients"""
        return [
            {
                'client_id': client_id,
                'ip': client['ip'],
                'port': client['port'],
                'mac': client.get('mac'),
                'connected_at': client['connected_at'],
                'active': client['active']
            }
            for client_id, client in self.clients.items()
        ]
    
    def _get_available_files(self):
        """Get list of files available for download"""
        files = []
        try:
            for filename in os.listdir(self.file_storage):
                filepath = os.path.join(self.file_storage, filename)
                if os.path.isfile(filepath):
                    files.append({
                        'filename': filename,
                        'size': os.path.getsize(filepath),
                        'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                    })
        except Exception as e:
            print(f"[Server] Error listing files: {e}")
        
        return files
    
    def _send_file_to_client(self, client_id, filename):
        """Send a file to a client"""
        filepath = os.path.join(self.file_storage, filename)
        
        if not os.path.exists(filepath):
            self._send_to_client(client_id, {
                'type': 'file_error',
                'error': 'File not found'
            })
            return
        
        try:
            filesize = os.path.getsize(filepath)
            
            # Send file metadata
            self._send_to_client(client_id, {
                'type': 'file_download_start',
                'filename': filename,
                'filesize': filesize
            })
            
            # Send file in chunks
            with open(filepath, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < filesize:
                    chunk = f.read(self.transfer_chunk_size)
                    if not chunk:
                        break
                    
                    client = self.clients.get(client_id)
                    if client and client['active']:
                        client['socket'].sendall(chunk)
                        bytes_sent += len(chunk)
            
            # Send completion message
            self._send_to_client(client_id, {
                'type': 'file_download_complete',
                'filename': filename,
                'bytes_sent': bytes_sent
            })
            
            print(f"[Server] Sent file {filename} to {client_id}")
            
            # Notify frontend
            if self.socketio:
                self.socketio.emit('file_transfer', {
                    'type': 'download',
                    'client_id': client_id,
                    'filename': filename,
                    'size': filesize,
                    'status': 'completed'
                })
                
        except Exception as e:
            print(f"[Server] Error sending file to {client_id}: {e}")
            self._send_to_client(client_id, {
                'type': 'file_error',
                'error': str(e)
            })
    
    def _receive_file_from_client(self, client_id, filename, filesize):
        """Receive a file from a client"""
        filepath = os.path.join(self.file_storage, filename)
        
        try:
            client = self.clients.get(client_id)
            if not client:
                return
            
            # Send acknowledgment
            self._send_to_client(client_id, {
                'type': 'file_upload_ready',
                'filename': filename
            })
            
            # Receive file in chunks
            with open(filepath, 'wb') as f:
                bytes_received = 0
                while bytes_received < filesize:
                    chunk = client['socket'].recv(min(self.transfer_chunk_size, filesize - bytes_received))
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_received += len(chunk)
            
            # Send completion message
            self._send_to_client(client_id, {
                'type': 'file_upload_complete',
                'filename': filename,
                'bytes_received': bytes_received
            })
            
            print(f"[Server] Received file {filename} from {client_id}")
            
            # Notify frontend
            if self.socketio:
                self.socketio.emit('file_transfer', {
                    'type': 'upload',
                    'client_id': client_id,
                    'filename': filename,
                    'size': bytes_received,
                    'status': 'completed'
                })
                
        except Exception as e:
            print(f"[Server] Error receiving file from {client_id}: {e}")
    
    def send_file_to_client(self, client_id, filename):
        """API method to send file to client"""
        if client_id not in self.clients:
            return {'success': False, 'error': 'Client not connected'}
        
        filepath = os.path.join(self.file_storage, filename)
        if not os.path.exists(filepath):
            return {'success': False, 'error': 'File not found'}
        
        # Start file transfer in a separate thread
        transfer_thread = threading.Thread(
            target=self._send_file_to_client,
            args=(client_id, filename),
            daemon=True
        )
        transfer_thread.start()
        
        return {'success': True, 'message': f'Sending {filename} to {client_id}'}
    
    def broadcast_message(self, message):
        """Send message to all connected clients"""
        success_count = 0
        for client_id in list(self.clients.keys()):
            if self._send_to_client(client_id, message):
                success_count += 1
        
        return {
            'success': True,
            'message': f'Message sent to {success_count}/{len(self.clients)} clients'
        }
    
    def get_server_status(self):
        """Get server status information"""
        return {
            'running': self.running,
            'host': self.host,
            'port': self.port,
            'connected_clients': len(self.clients),
            'clients': self.get_connected_clients()
        }
