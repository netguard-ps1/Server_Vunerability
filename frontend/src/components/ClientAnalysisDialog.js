import React, { useEffect, useRef } from 'react';
import { X, Shield, AlertTriangle, TrendingUp, Activity } from 'lucide-react';
import {
  PieChart, Pie, Cell, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar
} from 'recharts';

const ClientAnalysisDialog = ({ client, packets, onClose }) => {
  const dialogRef = useRef(null);

  useEffect(() => {
    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [onClose]);

  // Filter packets for this client
  const clientPackets = packets.filter(
    (p) => p.src_ip === client.ip || p.dst_ip === client.ip
  );

  // Calculate statistics
  const benignPackets = clientPackets.filter((p) => p.class === 'benign');
  const maliciousPackets = clientPackets.filter((p) => p.class === 'malicious');
  const totalPackets = clientPackets.length;

  const benignPercentage = totalPackets > 0 ? ((benignPackets.length / totalPackets) * 100).toFixed(1) : 0;
  const maliciousPercentage = totalPackets > 0 ? ((maliciousPackets.length / totalPackets) * 100).toFixed(1) : 0;

  // Classification pie chart data
  const classificationData = [
    { name: 'Benign', value: benignPackets.length, color: '#00ff88' },
    { name: 'Malicious', value: maliciousPackets.length, color: '#ff6b6b' }
  ].filter(item => item.value > 0);

  // Packet rate over time (benign vs malicious)
  const preparePacketRateData = () => {
    const timeGroups = {};
    
    clientPackets.forEach((packet) => {
      const time = new Date(packet.timestamp);
      const timeKey = `${time.getHours()}:${String(time.getMinutes()).padStart(2, '0')}`;
      
      if (!timeGroups[timeKey]) {
        timeGroups[timeKey] = { time: timeKey, benign: 0, malicious: 0 };
      }
      
      if (packet.class === 'benign') {
        timeGroups[timeKey].benign++;
      } else {
        timeGroups[timeKey].malicious++;
      }
    });
    
    return Object.values(timeGroups).sort((a, b) => a.time.localeCompare(b.time));
  };

  // Protocol distribution
  const prepareProtocolData = () => {
    const protocolCounts = {};
    
    clientPackets.forEach((packet) => {
      const protocol = packet.protocol || 'Unknown';
      protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
    });
    
    return Object.entries(protocolCounts)
      .map(([protocol, count]) => ({ protocol, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  };

  // Packet size distribution by classification
  const prepareSizeByClassData = () => {
    const sizeRanges = {
      '0-100': { benign: 0, malicious: 0 },
      '101-500': { benign: 0, malicious: 0 },
      '501-1000': { benign: 0, malicious: 0 },
      '1001-1500': { benign: 0, malicious: 0 },
      '1501+': { benign: 0, malicious: 0 }
    };
    
    clientPackets.forEach((packet) => {
      const size = packet.length || 0;
      const classification = packet.class === 'malicious' ? 'malicious' : 'benign';
      
      if (size <= 100) sizeRanges['0-100'][classification]++;
      else if (size <= 500) sizeRanges['101-500'][classification]++;
      else if (size <= 1000) sizeRanges['501-1000'][classification]++;
      else if (size <= 1500) sizeRanges['1001-1500'][classification]++;
      else sizeRanges['1501+'][classification]++;
    });
    
    return Object.entries(sizeRanges).map(([range, counts]) => ({
      range,
      benign: counts.benign,
      malicious: counts.malicious
    }));
  };

  // Threat assessment radar chart - Real metrics for security analysis
  const prepareThreatRadarData = () => {
    const totalPackets = clientPackets.length;
    const maliciousCount = maliciousPackets.length;
    const uniqueProtocols = new Set(clientPackets.map(p => p.protocol)).size;
    const avgPacketSize = clientPackets.reduce((sum, p) => sum + (p.length || 0), 0) / totalPackets || 0;
    
    // Calculate malicious packet rate (percentage)
    const maliciousRate = totalPackets > 0 ? (maliciousCount / totalPackets) * 100 : 0;
    
    // Protocol diversity score (more protocols = potentially suspicious)
    // Normal clients use 2-5 protocols, suspicious ones use many more
    const protocolScore = Math.min((uniqueProtocols / 8) * 100, 100);
    
    // Packet size anomaly score
    // Normal: 500-1000 bytes, Suspicious: very small (<100) or very large (>1400)
    let sizeScore = 0;
    if (avgPacketSize < 100) {
      sizeScore = 70; // Small packets can indicate scanning
    } else if (avgPacketSize > 1400) {
      sizeScore = 60; // Large packets can indicate data exfiltration
    } else if (avgPacketSize >= 500 && avgPacketSize <= 1000) {
      sizeScore = 20; // Normal range
    } else {
      sizeScore = 40; // Slightly unusual
    }
    
    // Traffic volume score (high volume = higher risk)
    // Normal: <50 packets, Medium: 50-200, High: >200
    let volumeScore = 0;
    if (totalPackets < 50) {
      volumeScore = 20;
    } else if (totalPackets < 200) {
      volumeScore = 50;
    } else {
      volumeScore = 80;
    }
    
    // Overall threat score (weighted average)
    const threatScore = (
      maliciousRate * 0.5 +        // 50% weight - most important
      protocolScore * 0.2 +         // 20% weight
      sizeScore * 0.15 +            // 15% weight
      volumeScore * 0.15            // 15% weight
    );
    
    return [
      {
        metric: 'Malicious Rate',
        value: maliciousRate,
        fullMark: 100,
        description: `${maliciousRate.toFixed(1)}% of packets are malicious`
      },
      {
        metric: 'Protocol Diversity',
        value: protocolScore,
        fullMark: 100,
        description: `${uniqueProtocols} different protocols used`
      },
      {
        metric: 'Packet Size Anomaly',
        value: sizeScore,
        fullMark: 100,
        description: `Avg: ${avgPacketSize.toFixed(0)} bytes`
      },
      {
        metric: 'Traffic Volume',
        value: volumeScore,
        fullMark: 100,
        description: `${totalPackets} total packets`
      },
      {
        metric: 'Overall Threat',
        value: threatScore,
        fullMark: 100,
        description: `Composite threat score: ${threatScore.toFixed(1)}/100`
      }
    ];
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div
        ref={dialogRef}
        className="bg-cyber-gray rounded-xl border border-cyber-blue/50 shadow-2xl w-full max-w-7xl max-h-[95vh] overflow-hidden flex flex-col"
      >
        {/* Header */}
        <div className="bg-cyber-dark border-b border-cyber-blue/30 p-6 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center space-x-3">
              <Activity className="w-7 h-7 text-purple-500" />
              <span>{client.isHost ? 'Host Analysis' : 'Client Analysis'}</span>
            </h2>
            <p className="text-sm text-gray-400 mt-1">
              Detailed analysis for <span className="text-cyber-blue font-mono font-semibold">{client.ip}</span>
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-cyber-blue/10 rounded-lg transition-colors"
          >
            <X className="w-6 h-6 text-gray-400 hover:text-white" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-cyber-dark rounded-lg p-4 border border-cyber-blue/30">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400">Total Packets</p>
                  <p className="text-2xl font-bold text-white">{totalPackets}</p>
                </div>
                <Activity className="w-8 h-8 text-cyber-blue opacity-50" />
              </div>
            </div>

            <div className="bg-cyber-dark rounded-lg p-4 border border-green-500/30">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400">Benign Packets</p>
                  <p className="text-2xl font-bold text-green-400">{benignPackets.length}</p>
                  <p className="text-xs text-gray-500 mt-1">{benignPercentage}% of total</p>
                </div>
                <Shield className="w-8 h-8 text-green-400 opacity-50" />
              </div>
            </div>

            <div className="bg-cyber-dark rounded-lg p-4 border border-red-500/30">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400">Malicious Packets</p>
                  <p className="text-2xl font-bold text-red-400">{maliciousPackets.length}</p>
                  <p className="text-xs text-gray-500 mt-1">{maliciousPercentage}% of total</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-red-400 opacity-50" />
              </div>
            </div>

            <div className="bg-cyber-dark rounded-lg p-4 border border-purple-500/30">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400">Threat Level</p>
                  <p className="text-2xl font-bold text-purple-400">
                    {maliciousPercentage > 50 ? 'HIGH' : maliciousPercentage > 20 ? 'MEDIUM' : 'LOW'}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">Based on malicious %</p>
                </div>
                <TrendingUp className="w-8 h-8 text-purple-400 opacity-50" />
              </div>
            </div>
          </div>

          {/* Charts Row 1 */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Classification Distribution */}
            <div className="bg-cyber-dark rounded-xl p-6 border border-cyber-blue/30">
              <h3 className="text-lg font-bold text-white mb-4">Classification Distribution</h3>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={classificationData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={100}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {classificationData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Threat Assessment Radar */}
            <div className="bg-cyber-dark rounded-xl p-6 border border-purple-500/30">
              <h3 className="text-lg font-bold text-white mb-2">Threat Assessment</h3>
              <p className="text-xs text-gray-400 mb-4">
                Real-time security metrics based on packet behavior analysis
              </p>
              <ResponsiveContainer width="100%" height={280}>
                <RadarChart data={prepareThreatRadarData()}>
                  <PolarGrid stroke="#1a1f3a" />
                  <PolarAngleAxis dataKey="metric" stroke="#666" tick={{ fontSize: 10 }} />
                  <PolarRadiusAxis stroke="#666" domain={[0, 100]} />
                  <Radar
                    name="Threat Level"
                    dataKey="value"
                    stroke="#b026ff"
                    fill="#b026ff"
                    fillOpacity={0.6}
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #b026ff' }}
                    formatter={(value, name, props) => [
                      `${value.toFixed(1)}%`,
                      props.payload.description
                    ]}
                  />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Charts Row 2 */}
          <div className="grid grid-cols-1 gap-6">
            {/* Packet Rate Over Time (Benign vs Malicious) */}
            <div className="bg-cyber-dark rounded-xl p-6 border border-cyber-blue/30">
              <h3 className="text-lg font-bold text-white mb-4">Packet Rate: Benign vs Malicious</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={preparePacketRateData()}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a1f3a" />
                  <XAxis dataKey="time" stroke="#666" tick={{ fontSize: 10 }} />
                  <YAxis stroke="#666" />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #00d9ff' }}
                  />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="benign"
                    stroke="#00ff88"
                    strokeWidth={2}
                    name="Benign Packets"
                  />
                  <Line
                    type="monotone"
                    dataKey="malicious"
                    stroke="#ff6b6b"
                    strokeWidth={2}
                    name="Malicious Packets"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Charts Row 3 */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Protocol Distribution */}
            <div className="bg-cyber-dark rounded-xl p-6 border border-cyber-blue/30">
              <h3 className="text-lg font-bold text-white mb-4">Protocol Distribution</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={prepareProtocolData()}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a1f3a" />
                  <XAxis dataKey="protocol" stroke="#666" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#666" />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #00d9ff' }}
                  />
                  <Bar dataKey="count" fill="#00d9ff" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Packet Size by Classification */}
            <div className="bg-cyber-dark rounded-xl p-6 border border-purple-500/30">
              <h3 className="text-lg font-bold text-white mb-4">Packet Size by Classification</h3>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={prepareSizeByClassData()}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a1f3a" />
                  <XAxis dataKey="range" stroke="#666" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#666" />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1a1f3a', border: '1px solid #b026ff' }}
                  />
                  <Legend />
                  <Bar dataKey="benign" fill="#00ff88" name="Benign" />
                  <Bar dataKey="malicious" fill="#ff6b6b" name="Malicious" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Client Info */}
          <div className="bg-cyber-dark rounded-xl p-6 border border-cyber-blue/30">
            <h3 className="text-lg font-bold text-white mb-4">Client Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <p className="text-xs text-gray-400 mb-1">IP Address</p>
                <p className="text-white font-mono font-semibold">{client.ip}</p>
              </div>
              <div>
                <p className="text-xs text-gray-400 mb-1">MAC Address</p>
                <p className="text-white font-mono">{client.mac}</p>
              </div>
              <div>
                <p className="text-xs text-gray-400 mb-1">Protocols Used</p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {client.protocols && client.protocols.length > 0 ? (
                    client.protocols.map((protocol) => (
                      <span
                        key={protocol}
                        className="px-2 py-0.5 bg-cyber-green/20 text-cyber-green text-xs rounded border border-cyber-green/30"
                      >
                        {protocol}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-gray-500">No protocols detected</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="bg-cyber-dark border-t border-cyber-blue/30 p-4 flex justify-end">
          <button
            onClick={onClose}
            className="px-6 py-2 bg-cyber-blue text-white rounded-lg hover:bg-cyber-blue/80 transition-all font-semibold"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default ClientAnalysisDialog;
