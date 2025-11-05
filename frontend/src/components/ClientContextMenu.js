import React, { useEffect, useRef } from 'react';
import { Filter, BarChart3, Copy } from 'lucide-react';

const ClientContextMenu = ({ position, client, onClose, onFilter, onAnalyze, isHost = false }) => {
  const menuRef = useRef(null);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        onClose();
      }
    };

    const handleEscape = (event) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleEscape);
    };
  }, [onClose]);

  const handleCopyIP = () => {
    navigator.clipboard.writeText(client.ip);
    onClose();
  };

  const handleCopyMAC = () => {
    navigator.clipboard.writeText(client.mac);
    onClose();
  };

  return (
    <div
      ref={menuRef}
      className="fixed bg-cyber-gray border border-cyber-blue/50 rounded-lg shadow-2xl z-50 min-w-[200px] overflow-hidden"
      style={{
        top: `${position.y}px`,
        left: `${position.x}px`,
      }}
    >
      {/* Header */}
      <div className="bg-cyber-dark px-4 py-2 border-b border-cyber-blue/30">
        <p className="text-xs text-gray-400">{isHost ? 'Host Actions' : 'Client Actions'}</p>
        <p className="text-sm font-mono text-cyber-blue font-semibold">{client.ip}</p>
      </div>

      {/* Menu Items */}
      <div className="py-1">
        <button
          onClick={() => {
            onFilter('srcIp', client.ip);
            onClose();
          }}
          className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-cyber-blue/20 hover:text-white transition-colors flex items-center space-x-2"
        >
          <Filter className="w-4 h-4" />
          <span>Filter by Source IP</span>
        </button>

        <button
          onClick={() => {
            onFilter('dstIp', client.ip);
            onClose();
          }}
          className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-cyber-blue/20 hover:text-white transition-colors flex items-center space-x-2"
        >
          <Filter className="w-4 h-4" />
          <span>Filter by Destination IP</span>
        </button>

        <button
          onClick={() => {
            onFilter('srcMac', client.mac);
            onClose();
          }}
          className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-cyber-blue/20 hover:text-white transition-colors flex items-center space-x-2"
        >
          <Filter className="w-4 h-4" />
          <span>Filter by MAC Address</span>
        </button>

        <div className="border-t border-cyber-blue/20 my-1"></div>

        <button
          onClick={() => {
            onAnalyze(client);
            onClose();
          }}
          className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-purple-500/20 hover:text-purple-400 transition-colors flex items-center space-x-2"
        >
          <BarChart3 className="w-4 h-4" />
          <span>{isHost ? 'Analyze Host' : 'Analyze Client'}</span>
        </button>

        <div className="border-t border-cyber-blue/20 my-1"></div>

        <button
          onClick={handleCopyIP}
          className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-cyber-blue/20 hover:text-white transition-colors flex items-center space-x-2"
        >
          <Copy className="w-4 h-4" />
          <span>Copy IP Address</span>
        </button>

        <button
          onClick={handleCopyMAC}
          className="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-cyber-blue/20 hover:text-white transition-colors flex items-center space-x-2"
        >
          <Copy className="w-4 h-4" />
          <span>Copy MAC Address</span>
        </button>
      </div>
    </div>
  );
};

export default ClientContextMenu;
