from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import timedelta, datetime
from config import Config
from packet_capture import PacketCapture
from pcap_analyzer import PcapAnalyzer
from client_server import ClientServerManager

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
Config.init_app()

# Initialize extensions
CORS(app, resources={r"/*": {"origins": Config.CORS_ORIGINS}})
socketio = SocketIO(app, cors_allowed_origins=Config.CORS_ORIGINS, async_mode='threading')
jwt = JWTManager(app)

# Initialize packet capture and analyzer
packet_capture = PacketCapture(socketio, Config.CAPTURE_DIR)
pcap_analyzer = PcapAnalyzer(Config.CAPTURE_DIR)

# Initialize client-server manager
client_server = ClientServerManager(host='0.0.0.0', port=9999, socketio=socketio)

# Simple user database (in production, use a real database)
users = {
    Config.ADMIN_EMAIL: {
        'password': generate_password_hash(Config.ADMIN_PASSWORD),
        'is_admin': True
    }
}

# ==================== Authentication Routes ====================

@app.route('/api/login', methods=['POST'])
def login():
    """Admin login endpoint"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'success': False, 'error': 'Email and password required'}), 400
    
    user = users.get(email)
    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(
            identity=email,
            expires_delta=timedelta(hours=24),
            additional_claims={'is_admin': user['is_admin']}
        )
        return jsonify({
            'success': True,
            'access_token': access_token,
            'is_admin': user['is_admin']
        })
    
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/api/verify', methods=['GET'])
@jwt_required()
def verify_token():
    """Verify JWT token"""
    current_user = get_jwt_identity()
    return jsonify({
        'success': True,
        'user': current_user,
        'is_admin': users.get(current_user, {}).get('is_admin', False)
    })

# ==================== Interface Routes ====================

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    result = packet_capture.get_interfaces()
    return jsonify(result)

# ==================== Capture Routes ====================

@app.route('/api/capture/start', methods=['POST'])
def start_capture():
    """Start packet capture - NO LOGIN REQUIRED"""
    data = request.get_json()
    interface = data.get('interface')
    ip_only = bool(data.get('ip_only', True))
    
    if not interface:
        return jsonify({'success': False, 'error': 'Interface required'}), 400
    
    result = packet_capture.start_capture(interface, ip_only)
    return jsonify(result)

@app.route('/api/capture/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture and save to file - NO LOGIN REQUIRED"""
    result = packet_capture.stop_capture()
    return jsonify(result)

@app.route('/api/capture/status', methods=['GET'])
def get_capture_status():
    """Get current capture status"""
    result = packet_capture.get_status()
    return jsonify(result)

# ==================== Client Agent Routes ====================

@app.route('/api/client/packet', methods=['POST'])
def receive_client_packet():
    """Receive packet from client agent"""
    data = request.get_json()
    result = packet_capture.add_client_packet(data)
    return jsonify(result)

# ==================== PCAP Routes ====================

@app.route('/api/pcap/list', methods=['GET'])
def list_pcap_files():
    """List all PCAP files"""
    result = pcap_analyzer.get_pcap_list()
    return jsonify(result)

@app.route('/api/pcap/download/<filename>', methods=['GET'])
def download_pcap(filename):
    """Download a PCAP file - NO LOGIN REQUIRED"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(Config.CAPTURE_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/pcap/upload', methods=['POST'])
def upload_pcap():
    """Upload and analyze a PCAP file"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        if not file.filename.endswith(('.pcap', '.cap', '.pcapng')):
            return jsonify({'success': False, 'error': 'Invalid file type. Only .pcap, .cap, and .pcapng files are supported'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(Config.CAPTURE_DIR, filename)
        file.save(filepath)
        
        # Analyze the uploaded file
        result = pcap_analyzer.analyze_pcap(filepath)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/pcap/analyze/<filename>', methods=['GET'])
def analyze_pcap(filename):
    """Analyze a specific PCAP file"""
    try:
        filename = secure_filename(filename)
        filepath = os.path.join(Config.CAPTURE_DIR, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        result = pcap_analyzer.analyze_pcap(filepath)
        
        # Return the analysis data directly if successful
        if result.get('success'):
            return jsonify(result['analysis'])
        else:
            return jsonify(result), 500
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== WebSocket Events ====================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    emit('connection_response', {'success': True, 'message': 'Connected to server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@socketio.on('request_status')
def handle_status_request():
    """Handle status request from client"""
    status = packet_capture.get_status()
    emit('status_update', status)

# ==================== Health Check ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'message': 'Server Vulnerability API is running',
        'version': '1.0.0'
    })

# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'error': 'Internal server error'}), 500

# ==================== Main ====================

# ==================== Client-Server Routes ====================

@app.route('/api/server/start', methods=['POST'])
@jwt_required()
def start_server():
    """Start the client-server socket"""
    result = client_server.start_server()
    return jsonify(result), 200 if result['success'] else 400

@app.route('/api/server/stop', methods=['POST'])
@jwt_required()
def stop_server():
    """Stop the client-server socket"""
    result = client_server.stop_server()
    return jsonify(result), 200 if result['success'] else 400

@app.route('/api/server/status', methods=['GET'])
@jwt_required()
def get_server_status():
    """Get server status and connected clients"""
    status = client_server.get_server_status()
    return jsonify({'success': True, 'status': status}), 200

@app.route('/api/server/clients', methods=['GET'])
@jwt_required()
def get_connected_clients():
    """Get list of connected clients"""
    clients = client_server.get_connected_clients()
    return jsonify({'success': True, 'clients': clients}), 200

@app.route('/api/server/disconnect/<client_id>', methods=['POST'])
@jwt_required()
def disconnect_client(client_id):
    """Disconnect a specific client"""
    result = client_server.disconnect_client(client_id)
    return jsonify(result), 200 if result['success'] else 400

@app.route('/api/server/files', methods=['GET'])
@jwt_required()
def list_server_files():
    """List files available on server"""
    files = client_server._get_available_files()
    return jsonify({'success': True, 'files': files}), 200

@app.route('/api/server/files/upload', methods=['POST'])
@jwt_required()
def upload_file_to_server():
    """Upload a file to server storage"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(client_server.file_storage, filename)
        file.save(filepath)
        
        return jsonify({
            'success': True,
            'message': f'File {filename} uploaded successfully',
            'filename': filename,
            'size': os.path.getsize(filepath)
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/server/files/<filename>', methods=['DELETE'])
@jwt_required()
def delete_server_file(filename):
    """Delete a file from server storage"""
    try:
        filepath = os.path.join(client_server.file_storage, secure_filename(filename))
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'success': True, 'message': f'File {filename} deleted'}), 200
        else:
            return jsonify({'success': False, 'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/server/files/<filename>/download', methods=['GET'])
@jwt_required()
def download_server_file(filename):
    """Download a file from server storage"""
    try:
        filepath = os.path.join(client_server.file_storage, secure_filename(filename))
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        else:
            return jsonify({'success': False, 'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/server/send-file', methods=['POST'])
@jwt_required()
def send_file_to_client():
    """Send a file to a connected client"""
    data = request.get_json()
    client_id = data.get('client_id')
    filename = data.get('filename')
    
    if not client_id or not filename:
        return jsonify({'success': False, 'error': 'client_id and filename required'}), 400
    
    result = client_server.send_file_to_client(client_id, filename)
    return jsonify(result), 200 if result['success'] else 400

@app.route('/api/server/broadcast', methods=['POST'])
@jwt_required()
def broadcast_message():
    """Broadcast a message to all connected clients"""
    data = request.get_json()
    message = data.get('message')
    
    if not message:
        return jsonify({'success': False, 'error': 'message required'}), 400
    
    result = client_server.broadcast_message({
        'type': 'broadcast',
        'message': message,
        'timestamp': datetime.now().isoformat()
    })
    return jsonify(result), 200

# ==================== Main ====================

if __name__ == '__main__':
    print("=" * 60)
    print("🔒 Server Vulnerability - Packet Capture System")
    print("=" * 60)
    print(f"🌐 Server running on http://localhost:{Config.FLASK_PORT}")
    print(f"📧 Admin Email: {Config.ADMIN_EMAIL}")
    print(f"🔑 Admin Password: {Config.ADMIN_PASSWORD}")
    print()
    print("✅ NO ADMIN PRIVILEGES REQUIRED!")
    print("✅ Packet capture works WITHOUT login")
    print("✅ Uses non-promiscuous mode (captures local traffic)")
    print(f"🔌 Client-Server port: 9999")
    print()
    print("⚠️  Change default credentials in production!")
    print("=" * 60)
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=Config.FLASK_PORT,
        debug=True,
        allow_unsafe_werkzeug=True
    )
