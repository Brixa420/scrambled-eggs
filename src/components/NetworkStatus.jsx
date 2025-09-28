import React from 'react';
import { Wifi, Globe, Network, Shield, RefreshCw, Zap, Users, Lock } from 'lucide-react';

const NetworkStatus = ({ 
  torStatus, 
  p2pStatus, 
  peers = 0, 
  dataTransferred = '0 MB',
  onRefresh 
}) => {
  const getStatusColor = (status) => {
    switch (status) {
      case 'connected': return 'text-green-400';
      case 'connecting': return 'text-yellow-400';
      case 'error': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className="bg-gradient-to-br from-gray-900 to-black border border-purple-700 rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
          <Network className="h-5 w-5 text-purple-400" />
          Network Status
        </h3>
        <button 
          onClick={onRefresh}
          className="p-1 hover:bg-purple-800 rounded-full transition-colors"
          title="Refresh status"
        >
          <RefreshCw className="h-4 w-4 text-purple-300" />
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Tor Status */}
        <div className="p-3 bg-black bg-opacity-30 rounded-lg border border-purple-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="h-5 w-5 text-orange-400" />
              <span className="text-purple-200">Tor Network</span>
            </div>
            <div className="flex items-center gap-1">
              <div className={`w-2 h-2 rounded-full ${getStatusColor(torStatus)}`}></div>
              <span className={`text-xs ${getStatusColor(torStatus)}`}>
                {torStatus.charAt(0).toUpperCase() + torStatus.slice(1)}
              </span>
            </div>
          </div>
          <div className="mt-2 text-xs text-purple-400 flex items-center gap-2">
            <Lock className="h-3 w-3" />
            <span>End-to-End Encrypted</span>
          </div>
        </div>

        {/* P2P Status */}
        <div className="p-3 bg-black bg-opacity-30 rounded-lg border border-purple-800">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Users className="h-5 w-5 text-blue-400" />
              <span className="text-purple-200">P2P Network</span>
            </div>
            <div className="flex items-center gap-1">
              <div className={`w-2 h-2 rounded-full ${getStatusColor(p2pStatus)}`}></div>
              <span className={`text-xs ${getStatusColor(p2pStatus)}`}>
                {p2pStatus.charAt(0).toUpperCase() + p2pStatus.slice(1)}
              </span>
            </div>
          </div>
          <div className="mt-2 text-xs text-purple-400 flex items-center justify-between">
            <div className="flex items-center gap-1">
              <Users className="h-3 w-3" />
              <span>{peers} {peers === 1 ? 'Peer' : 'Peers'}</span>
            </div>
            <div className="flex items-center gap-1">
              <Zap className="h-3 w-3 text-yellow-400" />
              <span>{dataTransferred}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Network Actions */}
      <div className="mt-4 flex flex-wrap gap-2">
        <button className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-purple-700 hover:bg-purple-600 rounded-lg text-sm font-medium transition-colors">
          <Wifi className="h-4 w-4" />
          <span>Network Settings</span>
        </button>
        <button className="flex-1 flex items-center justify-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm font-medium transition-colors">
          <Shield className="h-4 w-4" />
          <span>Security Center</span>
        </button>
      </div>
    </div>
  );
};

export default NetworkStatus;
