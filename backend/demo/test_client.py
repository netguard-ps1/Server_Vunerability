"""
Test Client for Server-Client Communication
Connects to the server and allows file transfer testing
"""

import socket
import json
import os
import time
import sys

SERVER_HOST = 'localhost'
SERVER_PORT = 9999

class TestClient:
    def __init__(self, host=SERVER_HOST, port=SERVER_PORT):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print(f"✓ Connected to server at {self.host}:{self.port}")
            
            # Send hello message
            self.send_message({
                'type': 'hello',
                'client_name': 'Test Client',
                'version': '1.0'
            })
            
            return True
        except Exception as e:
            print(f"✗ Failed to connect: {e}")
            return False
    
    def send_message(self, message):
        """Send a JSON message to the server"""
        try:
            data = json.dumps(message).encode('utf-8')
            self.socket.sendall(data)
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            print(f"\n✗ Server disconnected")
            self.connected = False
            return False
        except Exception as e:
            print(f"\n✗ Error sending message: {e}")
            self.connected = False
            return False
    
    def receive_message(self, timeout=5):
        """Receive a JSON message from the server"""
        try:
            self.socket.settimeout(timeout)
            data = self.socket.recv(4096)
            if not data:
                # Connection closed by server
                print("\n✗ Server closed the connection")
                self.connected = False
                return None
            return json.loads(data.decode('utf-8'))
        except socket.timeout:
            return None
        except ConnectionResetError:
            print("\n✗ Connection reset by server")
            self.connected = False
            return None
        except Exception as e:
            print(f"\n✗ Connection error: {e}")
            self.connected = False
            return None
    
    def request_file_list(self):
        """Request list of available files from server"""
        if not self.connected:
            print("✗ Not connected to server")
            return []
            
        print("\nRequesting file list from server...")
        if not self.send_message({'type': 'file_list_request'}):
            return []
        
        response = self.receive_message()
        if response:
            # Check for disconnect message
            if response.get('type') == 'disconnect':
                print(f"\n✗ Server disconnected: {response.get('reason', 'No reason given')}")
                self.connected = False
                return []
            elif response.get('type') == 'file_list':
                files = response.get('files', [])
                if files:
                    print(f"\nAvailable files ({len(files)}):")
                    for i, file in enumerate(files, 1):
                        print(f"  {i}. {file['filename']} ({file['size']} bytes)")
                else:
                    print("No files available on server")
                return files
        return []
    
    def download_file(self, filename):
        """Download a file from the server"""
        print(f"\nRequesting download: {filename}")
        self.send_message({
            'type': 'file_download_request',
            'filename': filename
        })
        
        # Wait for download start message
        response = self.receive_message()
        if response and response.get('type') == 'file_download_start':
            filesize = response.get('filesize')
            print(f"Receiving file: {filename} ({filesize} bytes)")
            
            # Receive file data
            # Note: In a real implementation, this would handle chunked transfer
            print("File transfer simulation - would receive data here")
            return True
        elif response and response.get('type') == 'file_error':
            print(f"Error: {response.get('error')}")
            return False
        return False
    
    def send_ping(self):
        """Send a ping to keep connection alive"""
        if not self.connected:
            print("✗ Not connected to server")
            return False
            
        if not self.send_message({'type': 'ping'}):
            return False
            
        response = self.receive_message(timeout=2)
        if response:
            if response.get('type') == 'disconnect':
                print(f"\n✗ Server disconnected: {response.get('reason', 'No reason given')}")
                self.connected = False
                return False
            elif response.get('type') == 'pong':
                print("✓ Ping successful")
                return True
        return False
    
    def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            try:
                self.socket.close()
                print("\n✓ Disconnected from server")
            except:
                pass
        self.connected = False
    
    def interactive_menu(self):
        """Interactive menu for testing"""
        while self.connected:
            print("\n" + "="*50)
            print("Test Client Menu")
            print("="*50)
            print("1. Request file list")
            print("2. Download file")
            print("3. Send ping")
            print("4. Disconnect")
            print("5. Exit")
            print("="*50)
            
            choice = input("\nEnter choice (1-5): ").strip()
            
            # Check if still connected before processing
            if not self.connected:
                print("\n" + "="*50)
                print("Connection lost. Exiting...")
                print("="*50)
                break
            
            if choice == '1':
                self.request_file_list()
            elif choice == '2':
                filename = input("Enter filename to download: ").strip()
                if filename:
                    self.download_file(filename)
            elif choice == '3':
                self.send_ping()
            elif choice == '4':
                self.disconnect()
                break
            elif choice == '5':
                self.disconnect()
                sys.exit(0)
            else:
                print("Invalid choice")
            
            # Check connection status after each operation
            if not self.connected:
                print("\n" + "="*50)
                print("⚠️  Disconnected from server")
                print("="*50)
                break

def main():
    print("="*50)
    print("Test Client for Server-Client Communication")
    print("="*50)
    print(f"\nConnecting to {SERVER_HOST}:{SERVER_PORT}...")
    print("Make sure the server is running!\n")
    
    client = TestClient()
    
    if client.connect():
        # Wait for welcome message
        response = client.receive_message()
        if response and response.get('type') == 'welcome':
            print(f"✓ Server says: {response.get('message')}")
        
        # Start interactive menu
        try:
            client.interactive_menu()
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            client.disconnect()
    else:
        print("\nFailed to connect to server.")
        print("\nMake sure:")
        print("  1. The backend server is running (python app.py)")
        print("  2. You've started the server from the Dashboard")
        print("  3. Port 9999 is not blocked by firewall")

if __name__ == "__main__":
    main()
