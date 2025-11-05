import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Network, Activity, Clock, Download, Filter, X, Play, Square, BarChart3, AlertCircle } from 'lucide-react';
import PacketTable from './PacketTable';
import ClientGrid from './ClientGrid';
import PacketDetailPanel from './PacketDetailPanel';
import ClientContextMenu from './ClientContextMenu';
import ClientAnalysisDialog from './ClientAnalysisDialog';
import socketService from '../utils/socket';
import { getInterfaces, startCapture, stopCapture, downloadPcap, getCaptureStatus, startServer as startServerAPI, stopServer as stopServerAPI, uploadFileToServer, getConnectedClients as getConnectedClientsAPI, disconnectClient as disconnectClientAPI, getServerStatus } from '../utils/api';

const Dashboard = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [packets, setPackets] = useState([]);
  const [clients, setClients] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [hasCapturedPackets, setHasCapturedPackets] = useState(false);
  const [capturedFilename, setCapturedFilename] = useState(null);
  const [showAllClients, setShowAllClients] = useState(false);
  const [malwareAlerts, setMalwareAlerts] = useState([]);
  const [contextMenu, setContextMenu] = useState(null);
  const [analysisDialog, setAnalysisDialog] = useState(null);
  
  // Check authentication status (guest mode)
  const isGuest = !localStorage.getItem('token');
  
  // Server state (for authenticated mode)
  const [serverRunning, setServerRunning] = useState(false);
  const [connectedClients, setConnectedClients] = useState([]);
  const [detectedHosts, setDetectedHosts] = useState([]);
  
  // Packet filter (for authenticated mode)
  const [packetTypeFilter, setPacketTypeFilter] = useState('all'); // 'all', 'client-server', 'unknown'
  
  // Notifications
  const [notifications, setNotifications] = useState([]);
  const [totalMalwareCount, setTotalMalwareCount] = useState(0);
  
  // Server files and socket clients
  const [socketClients, setSocketClients] = useState([]);
  
  // Filters
  const [showFilters, setShowFilters] = useState(false);
  const [showOnlyIP, setShowOnlyIP] = useState(true);
  const [classFilter, setClassFilter] = useState('');
  const [filters, setFilters] = useState({
    srcIp: '',
    dstIp: '',
    srcMac: '',
    dstMac: '',
    protocol: '',
  });

  // Load server status from backend
  const loadServerStatus = useCallback(async () => {
    if (!isGuest) {
      try {
        const response = await getServerStatus();
        if (response.data.success) {
          const status = response.data.status;
          setServerRunning(status.running);
          if (status.running && status.clients) {
            setSocketClients(status.clients);
          } else {
            setSocketClients([]);
          }
        }
      } catch (error) {
        console.error('Failed to load server status:', error);
        // If error, assume server is not running
        setServerRunning(false);
        setSocketClients([]);
      }
    }
  }, [isGuest]);

  // Load interfaces on mount with loading state
  useEffect(() => {
    const initializeDashboard = async () => {
      setLoading(true);
      await loadInterfaces();
      await loadCaptureStatus();
      
      // Load server status from backend for authenticated users
      if (!isGuest) {
        await loadServerStatus();
      }
      
      setLoading(false);
    };
    initializeDashboard();
  }, [isGuest, loadServerStatus]);

  // Poll server status periodically for authenticated users
  useEffect(() => {
    if (!isGuest) {
      // Poll server status every 3 seconds
      const interval = setInterval(loadServerStatus, 3000);
      return () => clearInterval(interval);
    }
  }, [isGuest, loadServerStatus]);

  // Setup WebSocket listeners
  useEffect(() => {
    socketService.connect();

    const handleNewPacket = (packet) => {
      setPackets((prev) => {
        const updated = [packet, ...prev];
        return updated.slice(0, 1000); // Keep last 1000 packets
      });
    };

    const handleClientConnected = (data) => {
      console.log('Client connected:', data);
      if (!isGuest) {
        addNotification(
          `Client connected: ${data.ip} (MAC: ${data.mac || 'N/A'})`,
          'success'
        );
        // Reload socket clients list
        loadSocketClients();
      }
    };

    const handleClientDisconnected = (data) => {
      console.log('Client disconnected:', data);
      if (!isGuest) {
        addNotification(
          `Client disconnected: ${data.client_id}`,
          'info'
        );
        // Reload socket clients list
        loadSocketClients();
      }
    };

    const handleClientsUpdate = (clientsList) => {
      // Check for new malware detections
      let malwareTotal = 0;
      clientsList.forEach(client => {
        malwareTotal += client.malicious_count || 0;
        
        if (client.malicious_count > 0) {
          // Check if this client already has an alert using functional update
          setMalwareAlerts(prev => {
            const existingAlert = prev.find(alert => alert.ip === client.ip);
            if (!existingAlert) {
              // New malware detection
              const newAlert = {
                id: Date.now() + Math.random(),
                ip: client.ip,
                mac: client.mac,
                count: client.malicious_count,
                timestamp: new Date()
              };
              
              // Auto-remove alert after 10 seconds
              setTimeout(() => {
                setMalwareAlerts(current => current.filter(a => a.id !== newAlert.id));
              }, 10000);
              
              return [...prev, newAlert];
            }
            return prev;
          });
        }
      });
      
      // Update total malware count
      setTotalMalwareCount(malwareTotal);
      
      // In authenticated mode, merge socket clients with packet capture clients
      if (!isGuest && serverRunning) {
        // Merge socket clients with packet capture clients
        const mergedClients = [...clientsList];
        
        // Add socket clients that don't have packet capture data yet
        socketClients.forEach(socketClient => {
          const existingClient = mergedClients.find(c => c.ip === socketClient.ip);
          if (!existingClient) {
            // Add socket client to the list with socket_connected flag
            mergedClients.push({
              ip: socketClient.ip,
              mac: socketClient.mac,
              packet_count: 0,
              benign_count: 0,
              malicious_count: 0,
              protocols: [],
              last_activity: socketClient.connected_at,
              active: socketClient.active,
              isConnected: true,
              socket_connected: true // Flag to indicate this is a socket client
            });
          } else {
            // Mark existing client as socket connected
            existingClient.socket_connected = true;
            existingClient.isConnected = true;
          }
        });
        
        // Separate into connected and detected
        const connected = mergedClients.filter(client => client.isConnected === true || client.socket_connected === true);
        const detected = mergedClients.filter(client => !client.isConnected && !client.socket_connected);
        
        // Notify when new client connects
        if (connected.length > connectedClients.length) {
          const newClient = connected[connected.length - 1];
          addNotification(`New client connected: ${newClient.ip}`, 'success');
        }
        
        setConnectedClients(connected);
        setDetectedHosts(detected);
      } else {
        // In guest mode or server not running, all are detected hosts
        setClients(clientsList);
        if (!isGuest) {
          setDetectedHosts(clientsList);
        }
      }
    };

    socketService.on('new_packet', handleNewPacket);
    socketService.on('clients_update', handleClientsUpdate);
    socketService.on('client_connected', handleClientConnected);
    socketService.on('client_disconnected', handleClientDisconnected);

    return () => {
      socketService.off('new_packet', handleNewPacket);
      socketService.off('clients_update', handleClientsUpdate);
      socketService.off('client_connected', handleClientConnected);
      socketService.off('client_disconnected', handleClientDisconnected);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isGuest, serverRunning]);

  const loadInterfaces = async () => {
    try {
      const response = await getInterfaces();
      if (response.data.success) {
        const interfacesList = response.data.interfaces;
        setInterfaces(interfacesList);
        // Set default interface - use name
        const defaultIface = response.data.default || interfacesList[0]?.name;
        setSelectedInterface(defaultIface);
      }
    } catch (error) {
      console.error('Failed to load interfaces:', error);
    }
  };

  const loadCaptureStatus = async () => {
    try {
      const response = await getCaptureStatus();
      setIsCapturing(response.data.is_capturing);
    } catch (error) {
      console.error('Failed to load capture status:', error);
    }
  };

  const handleStartCapture = async () => {
    if (!selectedInterface) {
      alert('Please select an interface');
      return;
    }

    try {
      const response = await startCapture(selectedInterface, showOnlyIP);
      if (response.data.success) {
        setIsCapturing(true);
        setPackets([]);
      } else {
        alert(response.data.error || 'Failed to start capture');
      }
    } catch (error) {
      alert(error.response?.data?.error || 'Failed to start capture. Make sure you have admin privileges.');
    }
  };

  const handleStopCapture = async () => {
    try {
      const response = await stopCapture();
      if (response.data.success) {
        setIsCapturing(false);
        setHasCapturedPackets(packets.length > 0);
        setCapturedFilename(response.data.filename); // Store filename for analysis
        alert(`Capture stopped. ${response.data.packet_count} packets captured.`);
      }
    } catch (error) {
      alert('Failed to stop capture');
    }
  };

  const handleDownloadPcap = async () => {
    try {
      if (!capturedFilename) {
        alert('No capture file available to download');
        return;
      }
      
      const response = await downloadPcap(capturedFilename);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', capturedFilename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download error:', error);
      alert('Failed to download PCAP file: ' + (error.response?.data?.error || error.message));
    }
  };

  const handleGoToAnalysis = () => {
    // Navigate to analysis page with the captured filename
    navigate('/analysis', { state: { filename: capturedFilename } });
  };

  const removeAlert = (alertId) => {
    setMalwareAlerts(prev => prev.filter(alert => alert.id !== alertId));
  };

  const getSortedClients = () => {
    // Sort clients: malicious first, then by packet count
    return [...clients].sort((a, b) => {
      // First priority: malicious count (descending)
      if ((b.malicious_count || 0) !== (a.malicious_count || 0)) {
        return (b.malicious_count || 0) - (a.malicious_count || 0);
      }
      // Second priority: packet count (descending)
      return b.packet_count - a.packet_count;
    });
  };

  const getDisplayedClients = () => {
    const sorted = getSortedClients();
    return showAllClients ? sorted : sorted.slice(0, 9);
  };

  const clearFilters = () => {
    setFilters({
      srcIp: '',
      dstIp: '',
      srcMac: '',
      dstMac: '',
      protocol: '',
    });
    setClassFilter('');
  };

  // Notification helper
  const addNotification = (message, type = 'info') => {
    const notification = {
      id: Date.now() + Math.random(),
      message,
      type // 'success', 'error', 'info', 'warning'
    };
    
    setNotifications(prev => [...prev, notification]);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      setNotifications(current => current.filter(n => n.id !== notification.id));
    }, 5000);
  };

  // Server control functions (authenticated mode)
  const handleStartServer = async () => {
    try {
      const response = await startServerAPI();
      if (response.data.success) {
        addNotification('Server started successfully! Waiting for client connections on port 9999...', 'success');
        console.log('Server started');
        // Reload server status from backend
        await loadServerStatus();
      } else {
        addNotification(response.data.error || 'Failed to start server', 'error');
      }
    } catch (error) {
      console.error('Failed to start server:', error);
      addNotification('Failed to start server: ' + (error.response?.data?.error || error.message), 'error');
    }
  };

  const handleStopServer = async () => {
    try {
      const response = await stopServerAPI();
      if (response.data.success) {
        addNotification('Server stopped', 'info');
        console.log('Server stopped');
        // Reload server status from backend
        await loadServerStatus();
        setConnectedClients([]);
      } else {
        addNotification(response.data.error || 'Failed to stop server', 'error');
      }
    } catch (error) {
      console.error('Failed to stop server:', error);
      addNotification('Failed to stop server: ' + (error.response?.data?.error || error.message), 'error');
    }
  };

  // Load connected socket clients
  const loadSocketClients = async () => {
    if (!isGuest && serverRunning) {
      try {
        const response = await getConnectedClientsAPI();
        if (response.data.success) {
          setSocketClients(response.data.clients);
        }
      } catch (error) {
        console.error('Failed to load socket clients:', error);
      }
    }
  };

  // Handle file upload
  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      const response = await uploadFileToServer(file);
      if (response.data.success) {
        addNotification(`File "${file.name}" uploaded successfully`, 'success');
      } else {
        addNotification(response.data.error || 'Failed to upload file', 'error');
      }
    } catch (error) {
      console.error('File upload error:', error);
      addNotification('Failed to upload file: ' + (error.response?.data?.error || error.message), 'error');
    }
    // Reset file input
    event.target.value = '';
  };

  // Disconnect a socket client
  const handleDisconnectSocketClient = async (clientId) => {
    try {
      const response = await disconnectClientAPI(clientId);
      if (response.data.success) {
        addNotification(`Client ${clientId} disconnected`, 'info');
        loadSocketClients();
      } else {
        addNotification(response.data.error || 'Failed to disconnect client', 'error');
      }
    } catch (error) {
      console.error('Disconnect error:', error);
      addNotification('Failed to disconnect client', 'error');
    }
  };

  const handleClientClick = (event, client, isHost = false) => {
    setContextMenu({
      position: { x: event.clientX, y: event.clientY },
      client: client,
      isHost: isHost
    });
  };

  const handleFilter = (filterType, value) => {
    // Clear all previous filters and apply only the new one
    setFilters({
      srcIp: '',
      dstIp: '',
      srcMac: '',
      dstMac: '',
      protocol: '',
      [filterType]: value
    });
    setClassFilter('');
    setShowFilters(true);
  };

  const handleAnalyzeClient = (client) => {
    // Check if this client is a host (detected host) or connected client
    const isHost = detectedHosts.some(h => h.ip === client.ip && h.mac === client.mac) || 
                   (isGuest && clients.some(c => c.ip === client.ip && c.mac === client.mac));
    setAnalysisDialog({ ...client, isHost });
  };

  const filteredPackets = packets.filter((packet) => {
    // Filter: Show only packets with IP addresses
    if (showOnlyIP && (!packet.src_ip || !packet.dst_ip)) return false;
    
    // Packet Type Filter (Authenticated Mode)
    if (!isGuest && serverRunning && packetTypeFilter !== 'all') {
      const connectedIPs = connectedClients.map(c => c.ip);
      const isClientServerPacket = connectedIPs.includes(packet.src_ip) || connectedIPs.includes(packet.dst_ip);
      
      if (packetTypeFilter === 'client-server' && !isClientServerPacket) return false;
      if (packetTypeFilter === 'unknown' && isClientServerPacket) return false;
    }
    
    if (filters.srcIp && !packet.src_ip.includes(filters.srcIp)) return false;
    if (filters.dstIp && !packet.dst_ip.includes(filters.dstIp)) return false;
    if (filters.srcMac && !packet.src_mac.toLowerCase().includes(filters.srcMac.toLowerCase())) return false;
    if (filters.dstMac && !packet.dst_mac.toLowerCase().includes(filters.dstMac.toLowerCase())) return false;
    if (filters.protocol && packet.protocol !== filters.protocol) return false;
    if (classFilter && (packet.class || '').toLowerCase() !== classFilter.toLowerCase()) return false;
    return true;
  });

  // Loading screen while fetching interfaces
  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-dark flex items-center justify-center">
        <div className="text-center space-y-6">
          {/* Animated Icon */}
          <div className="relative mx-auto w-24 h-24">
            <div className="absolute inset-0 border-4 border-cyber-blue/20 rounded-full"></div>
            <div className="absolute inset-0 border-4 border-transparent border-t-cyber-blue rounded-full animate-spin"></div>
            <Network className="w-12 h-12 text-cyber-blue absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2" />
          </div>
          
          {/* Loading Text */}
          <div>
            <h2 className="text-2xl font-bold text-white mb-2">Detecting Network Interfaces</h2>
            <p className="text-gray-400">Please wait while we scan available adapters...</p>
          </div>
          
          {/* Loading Dots */}
          <div className="flex justify-center space-x-2">
            <div className="w-3 h-3 bg-cyber-blue rounded-full animate-bounce" style={{animationDelay: '0ms'}}></div>
            <div className="w-3 h-3 bg-cyber-blue rounded-full animate-bounce" style={{animationDelay: '150ms'}}></div>
            <div className="w-3 h-3 bg-cyber-blue rounded-full animate-bounce" style={{animationDelay: '300ms'}}></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-dark pt-16">
      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Server Control (Authenticated Mode Only) - SHOW FIRST */}
        {!isGuest && (
          <div className="bg-cyber-gray rounded-xl p-6 border border-green-500/30">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-white mb-2 flex items-center space-x-2">
                  <Network className="w-6 h-6 text-green-500" />
                  <span>Server Control</span>
                </h2>
                <p className="text-sm text-gray-400">
                  {serverRunning ? 'Server is running and accepting client connections' : 'Start the server to accept client connections'}
                </p>
              </div>
              <button
                onClick={serverRunning ? handleStopServer : handleStartServer}
                className={`flex items-center space-x-2 px-6 py-3 rounded-lg font-semibold transition-all ${
                  serverRunning
                    ? 'bg-red-500 hover:bg-red-600 text-white'
                    : 'bg-green-500 hover:bg-green-600 text-white'
                }`}
              >
                {serverRunning ? (
                  <>
                    <Square className="w-5 h-5" />
                    <span>Stop Server</span>
                  </>
                ) : (
                  <>
                    <Play className="w-5 h-5" />
                    <span>Start Server</span>
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Connected Socket Clients (Authenticated Mode Only) */}
        {!isGuest && serverRunning && (
          <div className="bg-cyber-gray rounded-xl p-6 border border-purple-500/30">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                <Network className="w-6 h-6 text-purple-500" />
                <span>Connected Socket Clients ({socketClients.length})</span>
              </h2>
              <div>
                <label className="flex items-center space-x-2 px-4 py-2 bg-cyber-blue text-white rounded-lg hover:bg-cyber-blue/80 transition-all cursor-pointer">
                  <Download className="w-4 h-4" />
                  <span>Upload File</span>
                  <input
                    type="file"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
              </div>
            </div>
            
            {socketClients.length > 0 ? (
              <div className="space-y-2">
                {socketClients.map((client) => (
                  <div
                    key={client.client_id}
                    className="bg-cyber-dark p-4 rounded-lg border border-purple-500/30 hover:border-purple-500/60 transition-all"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-3">
                          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                          <div>
                            <p className="text-white font-semibold">{client.ip}</p>
                            <p className="text-sm text-gray-400">
                              MAC: {client.mac || 'N/A'} | Port: {client.port}
                            </p>
                            <p className="text-xs text-gray-500">
                              Connected: {new Date(client.connected_at).toLocaleTimeString()}
                            </p>
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => handleDisconnectSocketClient(client.client_id)}
                        className="px-3 py-1 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition-all text-sm"
                      >
                        Disconnect
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-400">
                <Network className="w-12 h-12 mx-auto mb-2 opacity-50" />
                <p>No clients connected</p>
                <p className="text-sm">Clients will appear here when they connect to port 9999</p>
              </div>
            )}
          </div>
        )}

        {/* Interface Selection and Control */}
        <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-3">
                <Network className="w-6 h-6 text-cyber-blue" />
                <h2 className="text-xl font-bold text-white">Interface Control</h2>
              </div>
              <div className="flex items-center space-x-2">
                {isCapturing && (
                  <div className="flex items-center space-x-2 px-3 py-1 bg-green-500/20 rounded-lg">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-green-500 text-sm font-semibold">CAPTURING</span>
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-4">
              {/* Interface Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Select Network Interface
                </label>
                <select
                  value={selectedInterface}
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  disabled={isCapturing}
                  className="w-full px-4 py-3 bg-cyber-dark border border-cyber-blue/30 rounded-lg text-white focus:outline-none focus:border-cyber-blue disabled:opacity-50"
                >
                  {interfaces.map((iface) => {
                    // Use name as value, description as display (like MyShark)
                    const value = iface.name || iface;
                    const display = iface.description || iface.name || iface;
                    return (
                      <option key={value} value={value}>
                        {display}
                      </option>
                    );
                  })}
                </select>
              </div>
              
              {/* Capture Options and Button */}
              <div className="flex items-center gap-4">
                <div className="flex items-center space-x-2 flex-1">
                  <input
                    type="checkbox"
                    id="captureOnlyIP"
                    checked={showOnlyIP}
                    onChange={(e) => setShowOnlyIP(e.target.checked)}
                    disabled={isCapturing}
                    className="w-4 h-4 rounded border-cyber-blue/30 bg-cyber-dark text-cyber-blue focus:ring-cyber-blue focus:ring-2"
                  />
                  <label htmlFor="captureOnlyIP" className="text-sm text-gray-300 cursor-pointer">
                    Capture only IP packets
                  </label>
                </div>
                
                {/* Capture Button */}
                {!isCapturing ? (
                  <button
                    onClick={handleStartCapture}
                    className="flex items-center justify-center space-x-2 px-6 py-3 bg-green-500 text-white rounded-lg hover:bg-green-600 transition-all font-semibold shadow-lg"
                  >
                    <Play className="w-5 h-5" />
                    <span>Start Capture</span>
                  </button>
                ) : (
                  <button
                    onClick={handleStopCapture}
                    className="flex items-center justify-center space-x-2 px-6 py-3 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-all font-semibold shadow-lg"
                  >
                    <Square className="w-5 h-5" />
                    <span>Stop Capture</span>
                  </button>
                )}
              </div>
            </div>

            {/* Action Buttons - Show after stopping capture */}
            {!isCapturing && hasCapturedPackets && (
              <div className="mt-4 flex gap-3">
                <button
                  onClick={handleDownloadPcap}
                  className="flex-1 flex items-center justify-center space-x-2 px-4 py-3 bg-cyber-blue text-white rounded-lg hover:bg-cyber-blue/80 transition-all font-semibold border border-cyber-blue"
                >
                  <Download className="w-5 h-5" />
                  <span>Download PCAP</span>
                </button>
                <button
                  onClick={handleGoToAnalysis}
                  className="flex-1 flex items-center justify-center space-x-2 px-4 py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-all font-semibold"
                >
                  <BarChart3 className="w-5 h-5" />
                  <span>Analyze Packets</span>
                </button>
              </div>
            )}
          </div>

        {/* Stats Bar */}
        <div className={`grid grid-cols-1 ${!isGuest ? 'md:grid-cols-4' : 'md:grid-cols-3'} gap-4`}>
          <div className="bg-cyber-gray rounded-xl p-4 border border-cyber-blue/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Packets</p>
                <p className="text-2xl font-bold text-cyber-blue">{filteredPackets.length}</p>
              </div>
              <Activity className="w-8 h-8 text-cyber-blue opacity-50" />
            </div>
          </div>

          <div className="bg-cyber-gray rounded-xl p-4 border border-cyber-green/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">{isGuest ? 'Detected Hosts' : 'Active Clients'}</p>
                <p className="text-2xl font-bold text-cyber-green">{clients.length}</p>
              </div>
              <Network className="w-8 h-8 text-cyber-green opacity-50" />
            </div>
          </div>

          {/* Malware Indicator - Authenticated Mode Only */}
          {!isGuest && (
            <div className="bg-cyber-gray rounded-xl p-4 border border-red-500/30">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm">Malware Detected</p>
                  <p className={`text-2xl font-bold ${totalMalwareCount > 0 ? 'text-red-500 animate-pulse' : 'text-gray-500'}`}>
                    {totalMalwareCount}
                  </p>
                </div>
                <AlertCircle className={`w-8 h-8 opacity-50 ${totalMalwareCount > 0 ? 'text-red-500' : 'text-gray-500'}`} />
              </div>
            </div>
          )}

          <div className="bg-cyber-gray rounded-xl p-4 border border-cyber-purple/30">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Capture Status</p>
                <p className="text-2xl font-bold text-cyber-purple">
                  {isCapturing ? 'Active' : 'Stopped'}
                </p>
              </div>
              <Clock className="w-8 h-8 text-cyber-purple opacity-50" />
            </div>
          </div>
        </div>

        {/* Client Grids - Guest Mode: Single Grid, Authenticated Mode: Dual Grids */}
        {isGuest ? (
          // Guest Mode: Single "Detected Hosts" Grid
          clients.length > 0 && (
            <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-white">Detected Hosts</h2>
                {clients.length > 9 && (
                  <button
                    onClick={() => setShowAllClients(!showAllClients)}
                    className="px-4 py-2 bg-cyber-blue/20 text-cyber-blue rounded-lg hover:bg-cyber-blue/30 transition-all text-sm font-semibold"
                  >
                    {showAllClients ? 'Show Less' : `Show All (${clients.length})`}
                  </button>
                )}
              </div>
              <ClientGrid clients={getDisplayedClients()} onClientClick={handleClientClick} isGuest={true} />
              {!showAllClients && clients.length > 9 && (
                <div className="mt-4 text-center">
                  <p className="text-gray-400 text-sm">
                    Showing 9 of {clients.length} hosts
                  </p>
                </div>
              )}
            </div>
          )
        ) : (
          // Authenticated Mode: Show grids regardless of server status
          <div className="space-y-6">
            {/* Connected Clients Grid - Only when server is running */}
            {serverRunning && connectedClients.length > 0 && (
              <div className="bg-cyber-gray rounded-xl p-6 border border-green-500/30">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-bold text-white flex items-center space-x-2">
                    <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                    <span>Connected Clients ({connectedClients.length})</span>
                  </h2>
                </div>
                <ClientGrid clients={connectedClients.slice(0, 9)} onClientClick={handleClientClick} isGuest={false} />
              </div>
            )}

            {/* Detected Hosts Grid - Always show when there are hosts */}
            {detectedHosts.length > 0 && (
              <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-xl font-bold text-white">Detected Hosts ({detectedHosts.length})</h2>
                </div>
                <ClientGrid clients={detectedHosts.slice(0, 9)} onClientClick={handleClientClick} isGuest={true} />
              </div>
            )}
          </div>
        )}

        {/* Filters */}
        <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold text-white">Packet Filters</h2>
            <div className="flex items-center gap-4">
              {/* Packet Type Filter (Authenticated Mode Only) */}
              {!isGuest && serverRunning && (
                <select
                  value={packetTypeFilter}
                  onChange={(e) => setPacketTypeFilter(e.target.value)}
                  className="px-3 py-2 bg-cyber-dark border border-cyber-blue/30 rounded-lg text-white text-sm focus:outline-none focus:border-cyber-blue"
                >
                  <option value="all">All Packets</option>
                  <option value="client-server">Client-Server Packets</option>
                  <option value="unknown">Unknown Packets</option>
                </select>
              )}
              
              <label className="flex items-center space-x-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={showOnlyIP}
                  onChange={(e) => setShowOnlyIP(e.target.checked)}
                  className="w-4 h-4 rounded border-cyber-blue/30 bg-cyber-dark text-cyber-blue focus:ring-cyber-blue focus:ring-2"
                />
                <span className="text-sm text-gray-300">Show only IP packets</span>
              </label>
              <button
                onClick={() => setShowFilters(!showFilters)}
                className="flex items-center space-x-2 px-4 py-2 bg-cyber-blue/20 text-cyber-blue rounded-lg hover:bg-cyber-blue/30 transition-all"
              >
                <Filter className="w-4 h-4" />
                <span>{showFilters ? 'Hide' : 'Show'} Filters</span>
              </button>
            </div>
          </div>

          {showFilters && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <input
                type="text"
                placeholder="Source IP (e.g., 192.168.1.1)"
                value={filters.srcIp}
                onChange={(e) => setFilters({ ...filters, srcIp: e.target.value })}
                className="px-4 py-2 bg-cyber-dark border border-cyber-blue/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue"
              />
              <input
                type="text"
                placeholder="Destination IP"
                value={filters.dstIp}
                onChange={(e) => setFilters({ ...filters, dstIp: e.target.value })}
                className="px-4 py-2 bg-cyber-dark border border-cyber-blue/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue"
              />
              <select
                value={filters.protocol}
                onChange={(e) => setFilters({ ...filters, protocol: e.target.value })}
                className="px-4 py-2 bg-cyber-dark border border-cyber-blue/30 rounded-lg text-white focus:outline-none focus:border-cyber-blue"
              >
                <option value="">All Protocols</option>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="FTP">FTP</option>
                <option value="HTTP">HTTP</option>
                <option value="DNS">DNS</option>
                <option value="ARP">ARP</option>
                <option value="ICMP">ICMP</option>
              </select>
              {/* Class filter */}
              <select
                value={classFilter}
                onChange={(e) => setClassFilter(e.target.value)}
                className="px-4 py-2 bg-cyber-dark border border-cyber-blue/30 rounded-lg text-white focus:outline-none focus:border-cyber-blue"
              >
                <option value="">All Classes</option>
                <option value="benign">Benign</option>
                <option value="malicious">Malicious</option>
              </select>
              <input
                type="text"
                placeholder="Source MAC"
                value={filters.srcMac}
                onChange={(e) => setFilters({ ...filters, srcMac: e.target.value })}
                className="px-4 py-2 bg-cyber-dark border border-cyber-blue/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue"
              />
              <input
                type="text"
                placeholder="Destination MAC"
                value={filters.dstMac}
                onChange={(e) => setFilters({ ...filters, dstMac: e.target.value })}
                className="px-4 py-2 bg-cyber-dark border border-cyber-blue/30 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-cyber-blue"
              />
              <button
                onClick={clearFilters}
                className="flex items-center justify-center space-x-2 px-4 py-2 bg-red-500/20 text-red-500 rounded-lg hover:bg-red-500/30 transition-all"
              >
                <X className="w-4 h-4" />
                <span>Clear Filters</span>
              </button>
            </div>
          )}
        </div>

        {/* Packet Table */}
        <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
          <h2 className="text-xl font-bold text-white mb-4">Live Packet Stream</h2>
          <PacketTable
            packets={filteredPackets}
            onPacketSelect={setSelectedPacket}
          />
          {/* Packet Count */}
          <div className="mt-4 text-center">
            <p className="text-xs text-gray-500">
              {filteredPackets.length === packets.length ? (
                `Showing all ${packets.length} packet${packets.length !== 1 ? 's' : ''}`
              ) : (
                `Showing ${filteredPackets.length} of ${packets.length} packet${packets.length !== 1 ? 's' : ''} (filtered)`
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Packet Detail Panel */}
      {selectedPacket && (
        <PacketDetailPanel
          packet={selectedPacket}
          onClose={() => setSelectedPacket(null)}
        />
      )}

      {/* Malware Alert Popups */}
      <div className="fixed bottom-4 right-4 space-y-2 z-50">
        {malwareAlerts.map((alert) => (
          <div
            key={alert.id}
            className="bg-red-500/10 border-2 border-red-500 rounded-lg p-4 shadow-2xl backdrop-blur-sm animate-slide-in-right max-w-sm"
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start space-x-3">
                <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center flex-shrink-0">
                  <span className="text-2xl">⚠</span>
                </div>
                <div>
                  <h4 className="text-red-400 font-bold text-lg mb-1">Malware Detected!</h4>
                  <p className="text-white font-mono text-sm mb-1">IP: {alert.ip}</p>
                  <p className="text-gray-300 text-xs">MAC: {alert.mac}</p>
                  <p className="text-red-300 text-sm mt-2">
                    {alert.count} malicious packet{alert.count > 1 ? 's' : ''} detected
                  </p>
                </div>
              </div>
              <button
                onClick={() => removeAlert(alert.id)}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Notification Popups */}
      <div className="fixed bottom-4 right-4 z-50 space-y-3 max-w-sm">
        {notifications.map((notification) => (
          <div
            key={notification.id}
            className={`px-4 py-3 rounded-lg shadow-lg border-l-4 backdrop-blur-md animate-slide-in-right ${
              notification.type === 'success' 
                ? 'bg-cyber-gray/95 border-green-500 text-white' 
                : notification.type === 'error' 
                ? 'bg-cyber-gray/95 border-red-500 text-white' 
                : notification.type === 'warning' 
                ? 'bg-cyber-gray/95 border-yellow-500 text-white' 
                : 'bg-cyber-gray/95 border-cyber-blue text-white'
            }`}
          >
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 mt-0.5">
                {notification.type === 'success' && (
                  <div className="w-5 h-5 rounded-full bg-green-500/20 flex items-center justify-center">
                    <div className="w-2 h-2 rounded-full bg-green-500"></div>
                  </div>
                )}
                {notification.type === 'error' && (
                  <div className="w-5 h-5 rounded-full bg-red-500/20 flex items-center justify-center">
                    <X className="w-3 h-3 text-red-500" />
                  </div>
                )}
                {notification.type === 'info' && (
                  <div className="w-5 h-5 rounded-full bg-cyber-blue/20 flex items-center justify-center">
                    <div className="w-2 h-2 rounded-full bg-cyber-blue"></div>
                  </div>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-200">{notification.message}</p>
              </div>
              <button
                onClick={() => setNotifications(prev => prev.filter(n => n.id !== notification.id))}
                className="flex-shrink-0 text-gray-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Client Context Menu */}
      {contextMenu && (
        <ClientContextMenu
          position={contextMenu.position}
          client={contextMenu.client}
          onClose={() => setContextMenu(null)}
          onFilter={handleFilter}
          onAnalyze={handleAnalyzeClient}
          isHost={contextMenu.isHost}
        />
      )}

      {/* Client Analysis Dialog */}
      {analysisDialog && (
        <ClientAnalysisDialog
          client={analysisDialog}
          packets={packets}
          onClose={() => setAnalysisDialog(null)}
        />
      )}
    </div>
  );
};

export default Dashboard;
