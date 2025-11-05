import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { Upload, FileText, BarChart3, PieChart, TrendingUp, Download, AlertTriangle, X } from 'lucide-react';
import { uploadPcap, analyzePcap, downloadPcap } from '../utils/api';
import { getServerStatus } from '../utils/api';
import { PieChart as RechartsPie, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, LineChart, Line, CartesianGrid } from 'recharts';
import PacketTable from './PacketTable';
import PacketDetailPanel from './PacketDetailPanel';

const Analysis = () => {
  const location = useLocation();
  const [selectedFile, setSelectedFile] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [autoLoadedFile, setAutoLoadedFile] = useState(null);
  const [showServerWarning, setShowServerWarning] = useState(false);
  
  // Check if user is authenticated and if server might be running
  const isAuthenticated = !!localStorage.getItem('token');

  // Check server status on mount
  useEffect(() => {
    const checkServerStatus = async () => {
      if (isAuthenticated) {
        try {
          const response = await getServerStatus();
          if (response.data.success && response.data.status.running) {
            setShowServerWarning(true);
          }
        } catch (error) {
          // Server status check failed, assume not running
          console.log('Server status check failed:', error);
        }
      }
    };
    checkServerStatus();
  }, [isAuthenticated]);

  const handleDownloadPcap = async () => {
    try {
      if (!autoLoadedFile) {
        alert('No file available to download');
        return;
      }
      
      const response = await downloadPcap(autoLoadedFile);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', autoLoadedFile);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Download error:', error);
      alert('Failed to download PCAP file: ' + (error.response?.data?.error || error.message));
    }
  };

  const getClassStats = () => {
    if (!analysis?.packets_data) return { benign: 0, malicious: 0 };
    
    const stats = { benign: 0, malicious: 0 };
    analysis.packets_data.forEach(packet => {
      const packetClass = (packet.class || 'benign').toLowerCase();
      if (packetClass === 'malicious') {
        stats.malicious++;
      } else {
        stats.benign++;
      }
    });
    return stats;
  };

  const COLORS = ['#00d9ff', '#00ff88', '#b026ff', '#ff6b6b', '#ffd93d', '#6bcf7f'];

  // Auto-load analysis if filename is passed from Dashboard
  useEffect(() => {
    const filename = location.state?.filename;
    if (filename && !autoLoadedFile) {
      setAutoLoadedFile(filename);
      loadAnalysis(filename);
    }
  }, [location.state, autoLoadedFile]);

  const loadAnalysis = async (filename) => {
    setLoading(true);
    try {
      const response = await analyzePcap(filename);
      console.log('Analysis response:', response.data); // Debug
      if (response.data) {
        setAnalysis(response.data);
      } else {
        alert('No analysis data received');
      }
    } catch (error) {
      console.error('Analysis error:', error);
      alert('Failed to analyze PCAP file: ' + (error.response?.data?.error || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      alert('Please select a PCAP file');
      return;
    }

    setLoading(true);
    try {
      const response = await uploadPcap(selectedFile);
      if (response.data.success) {
        setAnalysis(response.data.analysis);
      } else {
        alert(response.data.error || 'Failed to analyze PCAP');
      }
    } catch (error) {
      alert('Failed to upload and analyze PCAP file');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const prepareProtocolData = () => {
    if (!analysis?.protocols) return [];
    return Object.entries(analysis.protocols)
      .filter(([name, value]) => value > 0)  // Only show protocols with packets
      .map(([name, value]) => ({
        name,
        value,
      }));
  };

  const prepareTopSourcesData = () => {
    if (!analysis?.top_sources) return [];
    return Object.entries(analysis.top_sources)
      .slice(0, 10)
      .map(([ip, count]) => ({
        ip,
        count,
      }));
  };

  const prepareTopDestinationsData = () => {
    if (!analysis?.top_destinations) return [];
    return Object.entries(analysis.top_destinations)
      .slice(0, 10)
      .map(([ip, count]) => ({
        ip,
        count,
      }));
  };

  const prepareTimelineData = () => {
    if (!analysis?.timeline) return [];
    return analysis.timeline;
  };

  const prepareClassificationData = () => {
    const stats = getClassStats();
    return [
      { name: 'Benign', value: stats.benign, color: '#00ff88' },
      { name: 'Malicious', value: stats.malicious, color: '#ff6b6b' }
    ].filter(item => item.value > 0);
  };

  const preparePacketSizeData = () => {
    if (!analysis?.packets_data) return [];
    
    const sizeRanges = {
      '0-100': 0,
      '101-500': 0,
      '501-1000': 0,
      '1001-1500': 0,
      '1501+': 0
    };
    
    analysis.packets_data.forEach(packet => {
      const size = packet.length || 0;
      if (size <= 100) sizeRanges['0-100']++;
      else if (size <= 500) sizeRanges['101-500']++;
      else if (size <= 1000) sizeRanges['501-1000']++;
      else if (size <= 1500) sizeRanges['1001-1500']++;
      else sizeRanges['1501+']++;
    });
    
    return Object.entries(sizeRanges)
      .map(([range, count]) => ({ range, count }))
      .filter(item => item.count > 0);
  };

  // Loading screen while analyzing
  if (loading) {
    return (
      <div className="min-h-screen bg-cyber-dark flex items-center justify-center">
        <div className="text-center space-y-6 max-w-md mx-auto px-4">
          {/* Animated Icon */}
          <div className="relative mx-auto w-32 h-32">
            {/* Outer ring */}
            <div className="absolute inset-0 border-4 border-cyber-blue/10 rounded-full"></div>
            {/* Spinning ring */}
            <div className="absolute inset-0 border-4 border-transparent border-t-cyber-blue border-r-cyber-green rounded-full animate-spin"></div>
            {/* Inner icon */}
            <div className="absolute inset-0 flex items-center justify-center">
              <BarChart3 className="w-16 h-16 text-cyber-blue animate-pulse" />
            </div>
          </div>
          
          {/* Loading Text */}
          <div>
            <h2 className="text-3xl font-bold text-white mb-3">Analyzing Packets</h2>
            <p className="text-gray-400 text-lg mb-2">Processing PCAP file...</p>
            {autoLoadedFile && (
              <div className="mt-4 px-4 py-2 bg-cyber-blue/10 border border-cyber-blue/30 rounded-lg">
                <p className="text-sm text-cyber-blue font-mono break-all">{autoLoadedFile}</p>
              </div>
            )}
          </div>
          
          {/* Progress Indicator */}
          <div className="space-y-3">
            <div className="flex justify-center space-x-2">
              <div className="w-3 h-3 bg-cyber-blue rounded-full animate-bounce" style={{animationDelay: '0ms'}}></div>
              <div className="w-3 h-3 bg-cyber-green rounded-full animate-bounce" style={{animationDelay: '150ms'}}></div>
              <div className="w-3 h-3 bg-purple-500 rounded-full animate-bounce" style={{animationDelay: '300ms'}}></div>
            </div>
            <p className="text-sm text-gray-500">This may take a few seconds...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-cyber-dark pt-16">
      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Server Active Warning for Authenticated Users */}
        {isAuthenticated && showServerWarning && (
          <div className="bg-yellow-500/10 border-l-4 border-yellow-500 rounded-lg p-4 shadow-lg">
            <div className="flex items-start justify-between">
              <div className="flex items-start space-x-3">
                <AlertTriangle className="w-6 h-6 text-yellow-500 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-yellow-500 font-bold text-lg mb-1">Server Still Active</h3>
                  <p className="text-gray-300 text-sm">
                    Your server is currently running and accepting client connections. 
                    Consider stopping the server from the Dashboard if you're done with client operations.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowServerWarning(false)}
                className="text-gray-400 hover:text-white transition-colors ml-4"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}

        {/* Auto-loaded file indicator */}
        {autoLoadedFile && (
          <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4">
            <div className="flex items-center space-x-3">
              <BarChart3 className="w-5 h-5 text-green-500" />
              <div>
                <p className="text-green-500 font-semibold">Analysis Complete</p>
                <p className="text-sm text-gray-400">File: {autoLoadedFile}</p>
              </div>
            </div>
          </div>
        )}

        {/* Upload Section */}
        <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
          <div className="flex items-center space-x-3 mb-4">
            <Upload className="w-6 h-6 text-cyber-blue" />
            <h2 className="text-xl font-bold text-white">Upload PCAP File</h2>
          </div>

          <div className="space-y-3">
            <label className="block text-sm font-medium text-gray-400">
              Select PCAP File (.pcap, .cap, .pcapng)
            </label>
            <div className="flex flex-col md:flex-row gap-3">
              <div className="flex-1">
                <input
                  type="file"
                  accept=".pcap,.cap,.pcapng"
                  onChange={handleFileSelect}
                  className="w-full px-4 py-3 bg-cyber-dark border-2 border-cyber-blue/30 rounded-lg text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-cyber-blue file:text-white file:font-semibold hover:file:bg-cyber-blue/80 focus:outline-none focus:border-cyber-blue transition-all cursor-pointer"
                />
                {selectedFile && (
                  <div className="mt-2 flex items-center space-x-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <p className="text-sm text-green-400 font-medium">
                      {selectedFile.name} ({(selectedFile.size / 1024).toFixed(2)} KB)
                    </p>
                  </div>
                )}
              </div>
              <button
                onClick={handleUpload}
                disabled={!selectedFile || loading}
                className="px-6 py-3 bg-cyber-green text-cyber-dark rounded-lg hover:bg-cyber-green/80 transition-all font-semibold disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center space-x-2 whitespace-nowrap"
              >
                {loading ? (
                  <>
                    <div className="w-5 h-5 border-2 border-cyber-dark border-t-transparent rounded-full animate-spin"></div>
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <BarChart3 className="w-5 h-5" />
                    <span>Analyze PCAP</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Analysis Results */}
        {analysis && (
          <>
            {/* Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-cyber-gray rounded-xl p-4 border border-cyber-blue/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Total Packets</p>
                    <p className="text-2xl font-bold text-cyber-blue">{analysis.total_packets}</p>
                  </div>
                  <FileText className="w-8 h-8 text-cyber-blue opacity-50" />
                </div>
              </div>

              <div className="bg-cyber-gray rounded-xl p-4 border border-cyber-green/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Protocols</p>
                    <p className="text-2xl font-bold text-cyber-green">
                      {Object.keys(analysis.protocols || {}).length}
                    </p>
                  </div>
                  <BarChart3 className="w-8 h-8 text-cyber-green opacity-50" />
                </div>
              </div>

              <div className="bg-cyber-gray rounded-xl p-4 border border-cyber-purple/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Unique Sources</p>
                    <p className="text-2xl font-bold text-cyber-purple">
                      {Object.keys(analysis.top_sources || {}).length}
                    </p>
                  </div>
                  <TrendingUp className="w-8 h-8 text-cyber-purple opacity-50" />
                </div>
              </div>

              <div className="bg-cyber-gray rounded-xl p-4 border border-yellow-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Unique Destinations</p>
                    <p className="text-2xl font-bold text-yellow-500">
                      {Object.keys(analysis.top_destinations || {}).length}
                    </p>
                  </div>
                  <TrendingUp className="w-8 h-8 text-yellow-500 opacity-50" />
                </div>
              </div>
            </div>

            {/* Classification Stats */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-cyber-gray rounded-xl p-4 border border-green-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Benign Packets</p>
                    <p className="text-2xl font-bold text-green-400">{getClassStats().benign}</p>
                    <p className="text-xs text-gray-500 mt-1">
                      {((getClassStats().benign / analysis.total_packets) * 100).toFixed(1)}% of total
                    </p>
                  </div>
                  <div className="w-12 h-12 rounded-full bg-green-500/20 flex items-center justify-center">
                    <span className="text-2xl">✓</span>
                  </div>
                </div>
              </div>

              <div className="bg-cyber-gray rounded-xl p-4 border border-red-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Malicious Packets</p>
                    <p className="text-2xl font-bold text-red-400">{getClassStats().malicious}</p>
                    <p className="text-xs text-gray-500 mt-1">
                      {((getClassStats().malicious / analysis.total_packets) * 100).toFixed(1)}% of total
                    </p>
                  </div>
                  <div className="w-12 h-12 rounded-full bg-red-500/20 flex items-center justify-center">
                    <span className="text-2xl">⚠</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Charts Row 1: Pie Charts */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Classification Distribution */}
              <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center space-x-2">
                  <PieChart className="w-5 h-5 text-cyber-blue" />
                  <span>Classification</span>
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <RechartsPie>
                    <Pie
                      data={prepareClassificationData()}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(1)}%`}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {prepareClassificationData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </RechartsPie>
                </ResponsiveContainer>
              </div>

              {/* Protocol Distribution */}
              <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center space-x-2">
                  <PieChart className="w-5 h-5 text-cyber-blue" />
                  <span>Protocol Distribution</span>
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <RechartsPie>
                    <Pie
                      data={prepareProtocolData()}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(1)}%`}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {prepareProtocolData().map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </RechartsPie>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Charts Row 2: Top Source and Destination IPs */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Top Sources */}
              <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center space-x-2">
                  <BarChart3 className="w-5 h-5 text-cyber-blue" />
                  <span>Top Source IPs</span>
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={prepareTopSourcesData()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a1f3a" />
                    <XAxis dataKey="ip" stroke="#666" tick={{ fontSize: 10 }} />
                    <YAxis stroke="#666" />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #00d9ff' }}
                    />
                    <Bar dataKey="count" fill="#00d9ff" />
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Top Destinations */}
              <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center space-x-2">
                  <BarChart3 className="w-5 h-5 text-cyber-green" />
                  <span>Top Destination IPs</span>
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={prepareTopDestinationsData()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a1f3a" />
                    <XAxis dataKey="ip" stroke="#666" tick={{ fontSize: 10 }} />
                    <YAxis stroke="#666" />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #00d9ff' }}
                    />
                    <Bar dataKey="count" fill="#00ff88" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Charts Row 3: Timeline and Packet Size */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Timeline */}
              <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center space-x-2">
                  <TrendingUp className="w-5 h-5 text-cyber-green" />
                  <span>Packet Timeline</span>
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={prepareTimelineData()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a1f3a" />
                    <XAxis dataKey="time" stroke="#666" tick={{ fontSize: 10 }} />
                    <YAxis stroke="#666" />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #00d9ff' }}
                    />
                    <Line type="monotone" dataKey="count" stroke="#00ff88" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              {/* Packet Size Distribution */}
              <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center space-x-2">
                  <BarChart3 className="w-5 h-5 text-purple-500" />
                  <span>Packet Size Distribution</span>
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={preparePacketSizeData()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1a1f3a" />
                    <XAxis dataKey="range" stroke="#666" tick={{ fontSize: 11 }} label={{ value: 'Bytes', position: 'insideBottom', offset: -5 }} />
                    <YAxis stroke="#666" />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #b026ff' }}
                    />
                    <Bar dataKey="count" fill="#b026ff" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Packet Data Table */}
            <div className="bg-cyber-gray rounded-xl p-6 border border-cyber-blue/30">
              <h3 className="text-lg font-bold text-white mb-4">Packet Details</h3>
              <PacketTable
                packets={analysis.packets_data || []}
                onPacketSelect={setSelectedPacket}
              />
            </div>

            {/* Download Button */}
            {autoLoadedFile && (
              <div className="flex justify-center">
                <button
                  onClick={handleDownloadPcap}
                  className="flex items-center justify-center space-x-2 px-8 py-4 bg-cyber-blue text-white rounded-lg hover:bg-cyber-blue/80 transition-all font-semibold shadow-lg"
                >
                  <Download className="w-5 h-5" />
                  <span>Download PCAP File</span>
                </button>
              </div>
            )}
          </>
        )}

        {/* Empty State */}
        {!analysis && !loading && (
          <div className="bg-cyber-gray rounded-xl p-12 border border-cyber-blue/30 text-center">
            <Upload className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <h3 className="text-xl font-bold text-white mb-2">No Analysis Yet</h3>
            <p className="text-gray-400">
              Upload a PCAP file to view detailed analysis and statistics
            </p>
          </div>
        )}
      </div>

      {/* Packet Detail Panel */}
      {selectedPacket && (
        <PacketDetailPanel
          packet={selectedPacket}
          onClose={() => setSelectedPacket(null)}
        />
      )}
    </div>
  );
};

export default Analysis;
