import React from 'react';
import { format } from 'date-fns';

const PacketTable = ({ packets, onPacketSelect }) => {
  const getProtocolColor = (protocol) => {
    const colors = {
      TCP: 'text-blue-400',
      UDP: 'text-purple-400',
      FTP: 'text-red-400',
      HTTP: 'text-green-400',
      DNS: 'text-yellow-400',
      ARP: 'text-orange-400',
      ICMP: 'text-pink-400',
    };
    return colors[protocol] || 'text-gray-400';
  };

  if (packets.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-400">No packets captured yet. Start capturing to see live traffic.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <div className="max-h-[600px] overflow-y-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-cyber-dark border-b border-cyber-blue/30">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">No</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Time</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Delta</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Source IP</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Dest IP</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Source MAC</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Dest MAC</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Protocol</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Class</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Length</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-400 uppercase">Info</th>
            </tr>
          </thead>
          <tbody>
            {packets.map((packet, index) => (
              <tr
                key={`${packet.no}_${index}`}
                onClick={() => onPacketSelect(packet)}
                className="border-b border-cyber-blue/10 hover:bg-cyber-blue/5 cursor-pointer transition-colors"
              >
                <td className="px-4 py-3 text-gray-300 font-mono">{packet.no}</td>
                <td className="px-4 py-3 text-gray-300 font-mono text-xs">
                  {packet.timestamp || '-'}
                </td>
                <td className="px-4 py-3 text-yellow-400 font-mono text-xs">
                  {packet.delta_time !== undefined ? `${packet.delta_time.toFixed(6)}s` : '-'}
                </td>
                <td className="px-4 py-3 text-cyber-blue font-mono">{packet.src_ip || '-'}</td>
                <td className="px-4 py-3 text-cyber-green font-mono">{packet.dst_ip || '-'}</td>
                <td className="px-4 py-3 text-gray-400 font-mono text-xs">{packet.src_mac || '-'}</td>
                <td className="px-4 py-3 text-gray-400 font-mono text-xs">{packet.dst_mac || '-'}</td>
                <td className={`px-4 py-3 font-semibold ${getProtocolColor(packet.protocol)}`}>
                  {packet.protocol || '-'}
                </td>
                <td className="px-4 py-3">
                  {packet.class ? (
                    <span
                      className={
                        `px-2 py-1 rounded text-xs font-semibold ` +
                        (packet.class === 'malicious'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : packet.class === 'benign'
                          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                          : 'bg-gray-500/20 text-gray-300 border border-gray-500/30')
                      }
                    >
                      {packet.class}
                    </span>
                  ) : (
                    <span className="text-gray-400 text-xs">-</span>
                  )}
                </td>
                <td className="px-4 py-3 text-gray-300">{packet.length}</td>
                <td className="px-4 py-3 text-gray-400 text-xs truncate max-w-xs">
                  {packet.info || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default PacketTable;
