import React from 'react';
import { Snowflake, Thermometer, Shield, Zap, Wifi, Lock, Globe, Clock, Database, Cpu, ShieldCheck } from 'lucide-react';
import { useAppContext } from '../context/AppContext';

const AntarcticStatus = () => {
  const { aiStatus, toggleAntarcticNode } = useAppContext();
  const { antarcticNode } = aiStatus;

  if (!antarcticNode) return null;

  const getStatusColor = (status) => {
    switch (status) {
      case 'operational': return 'text-green-400';
      case 'degraded': return 'text-yellow-400';
      case 'critical': return 'text-red-400';
      default: return 'text-purple-400';
    }
  };

  const getSecurityLevelColor = (level) => {
    switch (level) {
      case 'maximum': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      default: return 'text-green-400';
    }
  };

  return (
    <div className="bg-gradient-to-br from-blue-900 to-indigo-900 border border-blue-700 rounded-xl p-4 shadow-xl backdrop-blur-sm">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Snowflake className="h-5 w-5 text-blue-300" />
          <h3 className="text-lg font-bold bg-gradient-to-r from-blue-300 to-blue-100 bg-clip-text text-transparent">
            Aurora Australis Data Center
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${
            antarcticNode.connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'
          }`}></div>
          <span className="text-xs">
            {antarcticNode.connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-blue-300" />
            <span className="text-sm text-blue-100">Location:</span>
            <span className="text-sm font-mono">{antarcticNode.location}</span>
          </div>
          
          <div className="flex items-center gap-2">
            <Thermometer className="h-4 w-4 text-blue-300" />
            <span className="text-sm text-blue-100">Temperature:</span>
            <span className="text-sm">{antarcticNode.temperature}</span>
          </div>
          
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-300" />
            <span className="text-sm text-blue-100">Security Level:</span>
            <span className={`text-sm font-medium ${getSecurityLevelColor(antarcticNode.securityLevel)}`}>
              {antarcticNode.securityLevel.toUpperCase()}
            </span>
          </div>
          
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-blue-300" />
            <span className="text-sm text-blue-100">Encryption:</span>
            <span className="text-sm font-mono">{antarcticNode.encryption}</span>
          </div>
        </div>
        
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Wifi className="h-4 w-4 text-blue-300" />
            <span className="text-sm text-blue-100">Ping:</span>
            <span className="text-sm">{antarcticNode.ping}</span>
          </div>
          
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-blue-300" />
            <span className="text-sm text-blue-100">Data Transferred:</span>
            <span className="text-sm">{antarcticNode.dataTransferred}</span>
          </div>
          
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-blue-300" />
            <span className="text-sm text-blue-100">Quantum Link:</span>
            <span className="text-sm">{antarcticNode.quantumLink}</span>
          </div>
          
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-blue-300" />
            <span className="text-sm text-blue-100">Zero Trust Score:</span>
            <span className="text-sm">{antarcticNode.zeroTrustScore}%</span>
          </div>
        </div>
      </div>
      
      <div className="flex items-center justify-between pt-2 border-t border-blue-800">
        <div className="flex items-center gap-2 text-xs text-blue-300">
          <Clock className="h-3 w-3" />
          <span>Last Sync: {new Date(antarcticNode.lastSync).toLocaleString()}</span>
        </div>
        
        <button
          onClick={toggleAntarcticNode}
          className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
            antarcticNode.connected
              ? 'bg-red-600 hover:bg-red-700 text-white'
              : 'bg-blue-600 hover:bg-blue-700 text-white'
          }`}
        >
          {antarcticNode.connected ? 'Disconnect' : 'Connect'}
        </button>
      </div>
    </div>
  );
};

export default AntarcticStatus;
