import React, { useState, useEffect, useRef } from 'react';
import { X, Info, Code } from 'lucide-react';
import { format } from 'date-fns';

const PacketDetailPanel = ({ packet, onClose }) => {
  const [activeTab, setActiveTab] = useState('summary');
  const panelRef = useRef(null);

  // Close panel when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (panelRef.current && !panelRef.current.contains(event.target)) {
        onClose();
      }
    };

    // Add event listener
    document.addEventListener('mousedown', handleClickOutside);

    // Cleanup
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [onClose]);

  const formatHex = (hexString) => {
    if (!hexString) return 'No data available';
    
    const bytes = hexString.match(/.{1,2}/g) || [];
    const lines = [];
    
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(4, '0');
      const hex = chunk.join(' ').padEnd(47, ' ');
      const ascii = chunk
        .map(byte => {
          const code = parseInt(byte, 16);
          return code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
        })
        .join('');
      
      lines.push(`${offset}  ${hex}  ${ascii}`);
    }
    
    return lines.join('\n');
  };

  return (
    <div 
      ref={panelRef}
      className="fixed inset-y-0 right-0 w-full md:w-2/3 lg:w-1/2 bg-cyber-gray border-l border-cyber-blue/30 shadow-2xl z-50 overflow-hidden flex flex-col"
    >
      {/* Header */}
      <div className="bg-cyber-dark border-b border-cyber-blue/30 p-4 flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Packet Details</h2>
          <p className="text-sm text-gray-400">Packet #{packet.no}</p>
        </div>
        <button
          onClick={onClose}
          className="p-2 hover:bg-cyber-blue/10 rounded-lg transition-colors"
        >
          <X className="w-6 h-6 text-gray-400" />
        </button>
      </div>

      {/* Tabs */}
      <div className="bg-cyber-dark border-b border-cyber-blue/30 px-4 flex space-x-1">
        <button
          onClick={() => setActiveTab('summary')}
          className={`flex items-center space-x-2 px-4 py-3 border-b-2 transition-colors ${
            activeTab === 'summary'
              ? 'border-cyber-blue text-cyber-blue'
              : 'border-transparent text-gray-400 hover:text-gray-300'
          }`}
        >
          <Info className="w-4 h-4" />
          <span>Summary</span>
        </button>
        <button
          onClick={() => setActiveTab('hex')}
          className={`flex items-center space-x-2 px-4 py-3 border-b-2 transition-colors ${
            activeTab === 'hex'
              ? 'border-cyber-blue text-cyber-blue'
              : 'border-transparent text-gray-400 hover:text-gray-300'
          }`}
        >
          <Code className="w-4 h-4" />
          <span>Hex View</span>
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
        {activeTab === 'summary' && (
          <div className="space-y-6">
            {/* Basic Info */}
            <div className="bg-cyber-dark rounded-lg p-4 border border-cyber-blue/30">
              <h3 className="text-lg font-semibold text-white mb-4">Basic Information</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-xs text-gray-400 mb-1">Packet Number</p>
                  <p className="text-white font-mono">{packet.no}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 mb-1">Timestamp</p>
                  <p className="text-white font-mono text-sm">
                    {packet.timestamp ? format(new Date(packet.timestamp), 'yyyy-MM-dd HH:mm:ss.SSS') : '-'}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 mb-1">Protocol</p>
                  <p className="text-cyber-blue font-semibold">{packet.protocol || 'Unknown'}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 mb-1">Length</p>
                  <p className="text-white">{packet.length} bytes</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 mb-1">Classification</p>
                  {packet.class ? (
                    <span
                      className={
                        `px-3 py-1 rounded text-sm font-semibold inline-block ` +
                        (packet.class === 'malicious'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : packet.class === 'benign'
                          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                          : 'bg-gray-500/20 text-gray-300 border border-gray-500/30')
                      }
                    >
                      {packet.class.toUpperCase()}
                    </span>
                  ) : (
                    <p className="text-gray-400">Unknown</p>
                  )}
                </div>
                {packet.delta_time !== undefined && (
                  <div>
                    <p className="text-xs text-gray-400 mb-1">Delta Time</p>
                    <p className="text-yellow-400 font-mono">{packet.delta_time.toFixed(6)}s</p>
                  </div>
                )}
              </div>
            </div>

            {/* Network Layer */}
            <div className="bg-cyber-dark rounded-lg p-4 border border-cyber-blue/30">
              <h3 className="text-lg font-semibold text-white mb-4">Network Layer</h3>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-gray-400 mb-1">Source IP</p>
                  <p className="text-cyber-blue font-mono text-lg">{packet.src_ip || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 mb-1">Destination IP</p>
                  <p className="text-cyber-green font-mono text-lg">{packet.dst_ip || 'N/A'}</p>
                </div>
              </div>
            </div>

            {/* Data Link Layer */}
            <div className="bg-cyber-dark rounded-lg p-4 border border-cyber-blue/30">
              <h3 className="text-lg font-semibold text-white mb-4">Data Link Layer</h3>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-gray-400 mb-1">Source MAC</p>
                  <p className="text-white font-mono">{packet.src_mac || 'N/A'}</p>
                </div>
                <div>
                  <p className="text-xs text-gray-400 mb-1">Destination MAC</p>
                  <p className="text-white font-mono">{packet.dst_mac || 'N/A'}</p>
                </div>
              </div>
            </div>

            {/* Additional Info */}
            <div className="bg-cyber-dark rounded-lg p-4 border border-cyber-blue/30">
              <h3 className="text-lg font-semibold text-white mb-4">Packet Summary</h3>
              <div className="bg-black/50 rounded p-3 overflow-x-auto">
                <p className="text-gray-300 text-sm font-mono whitespace-pre-wrap break-all">
                  {packet.info || 'No additional information available'}
                </p>
              </div>
            </div>

            {/* Packet Statistics */}
            <div className="bg-cyber-dark rounded-lg p-4 border border-purple-500/30">
              <h3 className="text-lg font-semibold text-white mb-4">Packet Statistics</h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-cyber-gray/50 rounded p-3">
                  <p className="text-xs text-gray-400 mb-1">Total Size</p>
                  <p className="text-white font-bold text-lg">{packet.length} bytes</p>
                </div>
                <div className="bg-cyber-gray/50 rounded p-3">
                  <p className="text-xs text-gray-400 mb-1">Hex Data Length</p>
                  <p className="text-white font-bold text-lg">{packet.raw ? (packet.raw.length / 2).toFixed(0) : 0} bytes</p>
                </div>
                {packet.delta_time !== undefined && (
                  <>
                    <div className="bg-cyber-gray/50 rounded p-3">
                      <p className="text-xs text-gray-400 mb-1">Time Since Last</p>
                      <p className="text-yellow-400 font-bold text-lg">{(packet.delta_time * 1000).toFixed(2)} ms</p>
                    </div>
                    <div className="bg-cyber-gray/50 rounded p-3">
                      <p className="text-xs text-gray-400 mb-1">Packet Rate</p>
                      <p className="text-cyan-400 font-bold text-lg">
                        {packet.delta_time > 0 ? (1 / packet.delta_time).toFixed(2) : '∞'} pkt/s
                      </p>
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* Address Information */}
            <div className="bg-cyber-dark rounded-lg p-4 border border-cyan-500/30">
              <h3 className="text-lg font-semibold text-white mb-4">Address Information</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 bg-cyber-gray/50 rounded">
                  <div>
                    <p className="text-xs text-gray-400 mb-1">Source</p>
                    <p className="text-cyber-blue font-mono text-sm">{packet.src_ip || 'N/A'}</p>
                    <p className="text-gray-400 font-mono text-xs mt-1">{packet.src_mac || 'N/A'}</p>
                  </div>
                  <div className="text-gray-500 text-2xl">→</div>
                  <div className="text-right">
                    <p className="text-xs text-gray-400 mb-1">Destination</p>
                    <p className="text-cyber-green font-mono text-sm">{packet.dst_ip || 'N/A'}</p>
                    <p className="text-gray-400 font-mono text-xs mt-1">{packet.dst_mac || 'N/A'}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Protocol Details */}
            <div className="bg-cyber-dark rounded-lg p-4 border border-green-500/30">
              <h3 className="text-lg font-semibold text-white mb-4">Protocol Details</h3>
              <div className="space-y-2">
                <div className="flex items-center justify-between p-2 bg-cyber-gray/50 rounded">
                  <span className="text-gray-400 text-sm">Protocol Type</span>
                  <span className="text-cyber-green font-semibold">{packet.protocol || 'Unknown'}</span>
                </div>
                <div className="flex items-center justify-between p-2 bg-cyber-gray/50 rounded">
                  <span className="text-gray-400 text-sm">Packet Number</span>
                  <span className="text-white font-mono">#{packet.no}</span>
                </div>
                {packet.class && (
                  <div className="flex items-center justify-between p-2 bg-cyber-gray/50 rounded">
                    <span className="text-gray-400 text-sm">Security Status</span>
                    <span
                      className={
                        `px-3 py-1 rounded text-xs font-semibold ` +
                        (packet.class === 'malicious'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : 'bg-green-500/20 text-green-400 border border-green-500/30')
                      }
                    >
                      {packet.class.toUpperCase()}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Client Info (if available) */}
            {packet.client_name && (
              <div className="bg-cyber-dark rounded-lg p-4 border border-cyber-green/30">
                <h3 className="text-lg font-semibold text-white mb-4">Client Information</h3>
                <p className="text-cyber-green font-semibold">
                  Captured by: {packet.client_name}
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'hex' && (
          <div className="bg-cyber-dark rounded-lg p-4 border border-cyber-blue/30">
            <h3 className="text-lg font-semibold text-white mb-4">Hexadecimal View</h3>
            <div className="bg-black rounded p-4 overflow-x-auto">
              <pre className="text-xs font-mono text-green-400">
                {formatHex(packet.raw)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PacketDetailPanel;
