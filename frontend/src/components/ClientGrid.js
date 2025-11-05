import React from 'react';
import { Monitor, Activity, Clock, Wifi } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

const ClientGrid = ({ clients, onClientClick, isGuest = false }) => {
  const handleClientClick = (event, client) => {
    event.preventDefault();
    if (onClientClick) {
      // Pass isGuest as isHost parameter to indicate if it's a detected host
      onClientClick(event, client, isGuest);
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {clients.map((client, index) => (
        <div
          key={`${client.ip}_${client.mac}_${index}`}
          className="bg-cyber-dark rounded-lg p-4 border border-cyber-blue/30 hover:border-cyber-blue/60 transition-all cursor-pointer"
          onClick={(e) => handleClientClick(e, client)}
        >
          {/* Header */}
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-2">
              <Monitor className="w-5 h-5 text-cyber-blue" />
              <span className="text-sm font-semibold text-gray-300">
                {isGuest ? `Host ${index + 1}` : 'Client'}
              </span>
              {client.socket_connected && (
                <div className="flex items-center space-x-1 px-2 py-0.5 bg-purple-500/20 rounded border border-purple-500/50">
                  <Wifi className="w-3 h-3 text-purple-400" />
                  <span className="text-xs text-purple-400">Socket</span>
                </div>
              )}
            </div>
            {client.active && (
              <div className="flex items-center space-x-1">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-xs text-green-500">Active</span>
              </div>
            )}
          </div>

          {/* IP Address */}
          <div className="mb-2">
            <p className="text-xs text-gray-400">IP Address</p>
            <p className="text-lg font-mono font-bold text-cyber-blue">{client.ip}</p>
          </div>

          {/* MAC Address */}
          <div className="mb-3">
            <p className="text-xs text-gray-400">MAC Address</p>
            <p className="text-sm font-mono text-gray-300">{client.mac}</p>
          </div>

          {/* Protocols */}
          <div className="mb-3">
            <p className="text-xs text-gray-400 mb-1">Protocols</p>
            <div className="flex flex-wrap gap-1">
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

          {/* Classification Stats */}
          <div className="mb-3 pt-3 border-t border-cyber-blue/20">
            <p className="text-xs text-gray-400 mb-2">Packet Classification</p>
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-green-500/10 border border-green-500/30 rounded px-2 py-1">
                <p className="text-xs text-gray-400">Benign</p>
                <p className="text-lg font-bold text-green-400">{client.benign_count || 0}</p>
              </div>
              <div className="bg-red-500/10 border border-red-500/30 rounded px-2 py-1">
                <p className="text-xs text-gray-400">Malicious</p>
                <p className="text-lg font-bold text-red-400">{client.malicious_count || 0}</p>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="flex items-center justify-between pt-3 border-t border-cyber-blue/20">
            <div className="flex items-center space-x-1">
              <Activity className="w-4 h-4 text-gray-400" />
              <span className="text-xs text-gray-400">
                {client.packet_count} packets
              </span>
            </div>
            {client.last_activity && (
              <div className="flex items-center space-x-1">
                <Clock className="w-4 h-4 text-gray-400" />
                <span className="text-xs text-gray-400">
                  {formatDistanceToNow(new Date(client.last_activity), { addSuffix: true })}
                </span>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

export default ClientGrid;
