import React, { useState, useRef, useEffect } from 'react';
import { useAppContext } from '../context/AppContext';
import { handleFileUpload, downloadFile } from '../utils/fileUtils';
import Menu from './Menu';
import AntarcticStatus from './AntarcticStatus';
import NetworkStatus from './NetworkStatus';
import { 
  Send, 
  Phone, 
  Video, 
  Paperclip, 
  Shield, 
  Settings, 
  Search, 
  MoreVertical,
  Lock,
  Users,
  Bell,
  Eye,
  EyeOff,
  CheckCircle,
  AlertTriangle,
  Minimize2,
  X,
  Plus,
  Zap,
  Clock,
  Globe,
  Folder,
  Key,
  Bot,
  Menu,
  Home,
  MessageSquare,
  FileText,
  Network,
  Brain,
  Download,
  Upload,
  Zap,
  Activity
} from 'lucide-react';

const ScrambledEggsApp = ({ onToggleClippy, onToggleAIChat }) => {
  const [selectedChat, setSelectedChat] = useState(0);
  const [message, setMessage] = useState('');
  const [isSecurityPanelOpen, setIsSecurityPanelOpen] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [activeView, setActiveView] = useState('chat');
  const [isClippyActive, setIsClippyActive] = useState(true);
  const [torStatus, setTorStatus] = useState('connected');
  const [aiEncryptionStatus, setAiEncryptionStatus] = useState('learning');
  const messagesEndRef = useRef(null);
  
  const handleClippyToggle = () => {
    onToggleClippy();
  };

  // Mock data
  const contacts = [
    { 
      id: 0, 
      name: 'Alice Johnson', 
      lastMessage: 'File encrypted and sent via Tor 🔐', 
      time: '2:34 PM', 
      unread: 0, 
      status: 'online',
      encryptionLevel: 'AI-Enhanced',
      lastSeen: 'now'
    },
    { 
      id: 1, 
      name: 'Bob Wilson', 
      lastMessage: 'Voice call ended - P2P secure', 
      time: '1:22 PM', 
      unread: 3, 
      status: 'offline',
      encryptionLevel: 'Scrambled Eggs Pro',
      lastSeen: '5 minutes ago'
    },
    { 
      id: 2, 
      name: 'Charlie Davis', 
      lastMessage: 'Thanks for the anonymous file drop', 
      time: '11:45 AM', 
      unread: 0, 
      status: 'away',
      encryptionLevel: 'AI-Adaptive',
      lastSeen: '1 hour ago'
    }
  ];

  const messages = [
    { id: 1, sender: 'Alice Johnson', content: 'The new AI encryption is incredible! It\'s adapting in real-time.', time: '2:30 PM', isMe: false, encrypted: true, encryptionType: 'AI-Enhanced' },
    { id: 2, sender: 'me', content: 'I know! Clippy helped me optimize the settings. The autonomous learning is amazing.', time: '2:31 PM', isMe: true, encrypted: true, encryptionType: 'Scrambled Eggs Pro' },
    { id: 3, sender: 'Alice Johnson', content: 'Sending you a file through Tor now', time: '2:32 PM', isMe: false, encrypted: true, hasFile: true, fileName: 'classified_data.enc', encryptionType: 'AI-Adaptive' },
    { id: 4, sender: 'me', content: 'Perfect! The P2P file sharing with AI encryption is flawless.', time: '2:33 PM', isMe: true, encrypted: true, encryptionType: 'Scrambled Eggs Pro' },
    { id: 5, sender: 'Alice Johnson', content: 'File encrypted and sent via Tor 🔐', time: '2:34 PM', isMe: false, encrypted: true, encryptionType: 'AI-Enhanced' }
  ];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = () => {
    if (message.trim()) {
      // In a real app, you would send the message here
      console.log('Message sent:', message);
      setMessage('');
    }
  };

  // Rest of the component code...
  // [Previous JSX content remains the same]

  return (
    <div className="h-screen bg-black text-white flex overflow-hidden relative">
      {/* Animated stars background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {[...Array(20)].map((_, i) => (
          <div 
            key={i}
            className="absolute text-purple-300 opacity-60"
            style={{
              top: `${Math.random() * 100}%`,
              left: `${Math.random() * 100}%`,
              animation: `pulse ${2 + Math.random() * 3}s infinite`,
              fontSize: `${Math.random() * 10 + 10}px`
            }}
          >
            {['✦', '✨', '⭐', '🌟', '🌙'][Math.floor(Math.random() * 5)]}
          </div>
        ))}
      </div>

      {/* Sidebar */}
      <div className="w-80 bg-gradient-to-b from-purple-900 to-black border-r border-purple-800 flex flex-col backdrop-blur-sm relative z-10">
        {/* Header */}
        <div className="p-4 border-b border-purple-800 bg-gradient-to-r from-purple-800 to-purple-900">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-r from-purple-400 to-purple-600 rounded-lg flex items-center justify-center shadow-lg">
                <span className="text-black font-bold text-sm">🥚</span>
              </div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-purple-300 to-purple-500 bg-clip-text text-transparent">Scrambled Eggs</h1>
            </div>
            <div className="flex items-center gap-2">
              <button 
                onClick={() => setIsMenuOpen(true)}
                className="p-2 hover:bg-purple-800 rounded-lg transition-colors relative"
              >
                <Menu className="h-5 w-5 text-purple-300" />
              </button>
              <button 
                onClick={() => setIsSecurityPanelOpen(!isSecurityPanelOpen)}
                className="p-2 hover:bg-purple-800 rounded-lg transition-colors relative"
                title="Security Settings"
              >
                <Shield className="h-5 w-5 text-purple-300" />
              </button>
              <button 
                onClick={handleClippyToggle}
                className="p-2 hover:bg-purple-800 rounded-lg transition-colors relative"
                title="Anarchist Clippy"
              >
                <Zap className="h-5 w-5 text-yellow-400" />
              </button>
            </div>
          </div>
          
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-3 h-4 w-4 text-purple-400" />
            <input 
              type="text" 
              placeholder="Search conversations... ✨"
              className="w-full bg-black bg-opacity-50 border border-purple-700 rounded-lg py-2 pl-10 pr-4 text-sm focus:outline-none focus:border-purple-500 placeholder-purple-400"
            />
          </div>
        </div>

        {/* Contacts List */}
        <div className="flex-1 overflow-y-auto">
          {contacts.map((contact) => (
            <div
              key={contact.id}
              onClick={() => setSelectedChat(contact.id)}
              className={`p-4 border-b border-purple-800 cursor-pointer hover:bg-purple-900 hover:bg-opacity-50 transition-all duration-300 ${
                selectedChat === contact.id ? 'bg-gradient-to-r from-purple-800 to-purple-900 border-l-4 border-l-purple-400 shadow-lg' : ''
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <div className="w-10 h-10 bg-gradient-to-r from-purple-500 to-purple-700 rounded-full flex items-center justify-center shadow-md border border-purple-400">
                      <span className="text-white font-semibold text-sm">
                        {contact.name.split(' ').map(n => n[0]).join('')}
                      </span>
                    </div>
                    <div className={`absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-black ${
                      contact.status === 'online' ? 'bg-purple-300' : 
                      contact.status === 'away' ? 'bg-purple-500' : 'bg-gray-600'
                    }`}></div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="font-medium truncate text-white">{contact.name}</h3>
                      <span className="text-purple-300">🧠</span>
                    </div>
                    <p className="text-sm text-purple-300 truncate">{contact.lastMessage}</p>
                    <p className="text-xs text-purple-500">{contact.encryptionLevel}</p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1">
                  <span className="text-xs text-purple-400">{contact.time}</span>
                  {contact.unread > 0 && (
                    <span className="bg-gradient-to-r from-purple-400 to-purple-600 text-white text-xs rounded-full px-2 py-0.5 min-w-[1.25rem] text-center shadow-md">
                      {contact.unread}
                    </span>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
        
        {/* Add Contact Button */}
        <div className="p-4 border-t border-purple-800">
          <button className="w-full bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-500 hover:to-purple-600 text-white font-medium py-2 px-4 rounded-lg transition-all duration-300 flex items-center justify-center gap-2 shadow-lg">
            <Plus className="h-4 w-4" />
            Add Contact ✨
          </button>
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col relative z-10">
        {/* Chat Header */}
        <div className="bg-gradient-to-r from-purple-900 to-black border-b border-purple-800 p-4 flex items-center justify-between backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-r from-purple-500 to-purple-700 rounded-full flex items-center justify-center shadow-md border border-purple-400">
              <span className="text-white font-semibold text-sm">
                {contacts[selectedChat].name.split(' ').map(n => n[0]).join('')}
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-semibold text-white">{contacts[selectedChat].name}</h2>
                <div className="flex items-center gap-1">
                  <span className="text-sm text-purple-300">🧠</span>
                  <span className="text-xs text-purple-400">AI-Enhanced</span>
                </div>
              </div>
              <div className="flex items-center gap-2 text-sm text-purple-400">
                <div className={`w-2 h-2 rounded-full ${
                  contacts[selectedChat].status === 'online' ? 'bg-purple-300' : 
                  contacts[selectedChat].status === 'away' ? 'bg-purple-500' : 'bg-gray-600'
                }`}></div>
                <span>{contacts[selectedChat].status} • {contacts[selectedChat].encryptionLevel}</span>
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <button className="p-2 hover:bg-purple-800 rounded-lg transition-colors">
              <Phone className="h-5 w-5 text-purple-300" />
            </button>
            <button className="p-2 hover:bg-purple-800 rounded-lg transition-colors">
              <Video className="h-5 w-5 text-purple-400" />
            </button>
            <button className="p-2 hover:bg-purple-800 rounded-lg transition-colors">
              <Globe className="h-5 w-5 text-green-400" title="Tor Active" />
            </button>
            <button className="p-2 hover:bg-purple-800 rounded-lg transition-colors">
              <MoreVertical className="h-5 w-5 text-purple-300" />
            </button>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-gradient-to-b from-black to-purple-950">
          {messages.map((msg) => (
            <div key={msg.id} className={`flex ${msg.isMe ? 'justify-end' : 'justify-start'}` }>
              <div className={`max-w-xs lg:max-w-md px-4 py-2 rounded-2xl ${
                msg.isMe 
                  ? 'bg-gradient-to-r from-purple-500 to-purple-700 text-white shadow-lg' 
                  : 'bg-gradient-to-r from-purple-900 to-black border border-purple-800 text-white'
              }`}>
                {msg.hasFile && (
                  <div className="mb-2 p-2 bg-black bg-opacity-30 rounded-lg flex items-center gap-2 border border-purple-600">
                    <Paperclip className="h-4 w-4 text-purple-300" />
                    <span className="text-sm text-purple-200">{msg.fileName}</span>
                    <span className="text-xs text-green-400">🔐</span>
                  </div>
                )}
                <p className="text-sm">{msg.content}</p>
                <div className="flex items-center justify-between mt-1">
                  <span className={`text-xs ${msg.isMe ? 'text-purple-200' : 'text-purple-400'}` }>
                    {msg.time}
                  </span>
                  <div className="flex items-center gap-1">
                    {msg.encrypted && (
                      <span className={`text-sm ${msg.isMe ? 'text-purple-200' : 'text-purple-300'}` }>🧠</span>
                    )}
                    <span className={`text-xs ${msg.isMe ? 'text-purple-200' : 'text-purple-400'}` }>
                      {msg.encryptionType}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Message Input */}
        <div className="bg-gradient-to-r from-purple-900 to-black border-t border-purple-800 p-4 backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <button className="p-2 hover:bg-purple-800 rounded-lg transition-colors">
              <Paperclip className="h-5 w-5 text-purple-400" />
            </button>
            <div className="flex-1 relative">
              <input
                type="text"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                placeholder="Type a message... AI is learning your patterns ✨"
                className="w-full bg-black bg-opacity-50 border border-purple-700 rounded-lg py-3 px-4 pr-24 text-sm focus:outline-none focus:border-purple-500 text-white placeholder-purple-400"
              />
              <div className="absolute right-3 top-3 flex items-center gap-2">
                <span className="text-blue-400">🧠</span>
                <span className="text-xs text-purple-400">AI-AES</span>
              </div>
            </div>
            <button 
              onClick={handleSendMessage}
              className="bg-gradient-to-r from-purple-600 to-purple-700 hover:from-purple-500 hover:to-purple-600 text-white p-3 rounded-lg transition-all duration-300 shadow-lg"
            >
              <Send className="h-4 w-4" />
            </button>
          </div>
          
          {/* Enhanced Security Status Bar */}
          <div className="flex items-center justify-between mt-3 text-xs text-purple-400">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span>Tor Connected ✨</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="text-blue-400">🧠</span>
                <span>AI Encryption Active</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="text-purple-300">⭐</span>
                <span>P2P Network</span>
              </div>
              <div className="flex items-center gap-1">
                <Bot className="h-3 w-3 text-blue-400" />
                <span>Clippy Monitoring</span>
              </div>
            </div>
            <span className="text-purple-500">Autonomous • Private • Secure ✦</span>
          </div>
        </div>
      </div>


      {/* Security Panel */}
      {isSecurityPanelOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-70 z-40" onClick={() => setIsSecurityPanelOpen(false)}>
          <div className="absolute top-16 right-4 w-80 bg-gradient-to-b from-purple-900 to-black border border-purple-700 rounded-lg shadow-2xl p-4 z-50 backdrop-blur-sm" onClick={e => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-white font-semibold flex items-center gap-2">
                  <Shield className="h-5 w-5 text-purple-300" />
                  Scrambled Eggs Security
                </h3>
                <p className="text-xs text-purple-400 mt-1">All systems operational</p>
              </div>
              <button 
                onClick={() => setIsSecurityPanelOpen(false)}
                className="p-1 hover:bg-purple-800 rounded-full transition-colors"
              >
                <X className="h-4 w-4 text-purple-300" />
              </button>
            </div>
            
            <div className="space-y-3 mb-4">
              {/* Antarctic Data Center Status */}
              <div className="p-3 bg-gradient-to-br from-blue-900 to-indigo-900 border border-blue-700 rounded-lg shadow-lg">
                <AntarcticStatus />
              </div>
              
              <div className="p-3 bg-black bg-opacity-30 rounded-lg border border-purple-800">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-purple-200 font-medium">AI Encryption</span>
                  <div className="flex items-center gap-1 px-2 py-0.5 bg-purple-900 bg-opacity-50 rounded-full">
                    <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                    <span className="text-blue-400 text-xs">Active</span>
                  </div>
                </div>
                <div className="mt-2">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-purple-400">Learning Progress</span>
                    <span className="text-blue-400">{aiStatus.progress}%</span>
                  </div>
                  <div className="w-full bg-gray-800 rounded-full h-1.5">
                    <div 
                      className="bg-gradient-to-r from-blue-400 to-purple-500 h-1.5 rounded-full" 
                      style={{ width: `${aiStatus.progress}%` }}
                    ></div>
                  </div>
                  <div className="text-xs text-purple-400 mt-1">
                    Last trained: {aiStatus.lastTrained} • Accuracy: {aiStatus.accuracy}
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 bg-black bg-opacity-30 rounded-lg border border-purple-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-purple-200 text-sm">Base Encryption</span>
                    <span className="text-green-400 text-xs">AES-256-GCM</span>
                  </div>
                  <div className="text-xs text-purple-400">Military Grade</div>
                </div>
                
                <div className="p-3 bg-black bg-opacity-30 rounded-lg border border-purple-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-purple-200 text-sm">Tor Network</span>
                    <div className="flex items-center gap-1">
                      <div className={`w-2 h-2 rounded-full ${torStatus === 'connected' ? 'bg-green-400' : 'bg-red-400'}`}></div>
                      <span className="text-xs">{torStatus === 'connected' ? 'Connected' : 'Offline'}</span>
                    </div>
                  </div>
                  <div className="text-xs text-purple-400">
                    {torStatus === 'connected' ? 'Anonymous routing active' : 'Connection unstable'}
                  </div>
                </div>
                
                <div className="p-3 bg-black bg-opacity-30 rounded-lg border border-purple-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-purple-200 text-sm">P2P Network</span>
                    <span className="text-yellow-400 text-xs">Active</span>
                  </div>
                  <div className="text-xs text-purple-400">Direct connections: 5</div>
                </div>
                
                <div className="p-3 bg-black bg-opacity-30 rounded-lg border border-purple-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-purple-200 text-sm">Autonomous Mode</span>
                    <span className="text-purple-300 text-xs">✦ Active</span>
                  </div>
                  <div className="text-xs text-purple-400">AI-managed security</div>
                </div>
              </div>
              
              <div className="p-3 bg-black bg-opacity-30 rounded-lg border border-purple-800">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-purple-200 text-sm font-medium">Threat Detection</span>
                  <span className="text-green-400 text-xs">No threats found</span>
                </div>
                <div className="flex items-center justify-between text-xs">
                  <span className="text-purple-400">Last scan: Just now</span>
                  <button className="text-blue-400 hover:text-blue-300">Run scan</button>
                </div>
              </div>
            </div>
            
            <div className="space-y-2">
              <button 
                className="w-full bg-gradient-to-r from-purple-600 to-purple-800 hover:from-purple-500 hover:to-purple-700 text-white py-2 px-4 rounded transition-all duration-300 shadow-lg text-sm font-medium flex items-center justify-center gap-2"
                onClick={() => {
                  // In a real app, this would reset AI learning
                  alert('AI security settings would be reset here');
                }}
              >
                <RefreshCw className="h-4 w-4" />
                Reset AI Learning
              </button>
              
              <button 
                className="w-full bg-gradient-to-r from-red-600 to-red-800 hover:from-red-500 hover:to-red-700 text-white py-2 px-4 rounded transition-all duration-300 shadow-lg text-sm font-medium flex items-center justify-center gap-2"
                onClick={() => {
                  if (window.confirm('Are you sure you want to lock and close all secure sessions?')) {
                    // In a real app, this would lock all sessions
                    alert('All secure sessions would be locked here');
                  }
                }}
              >
                <Lock className="h-4 w-4" />
                Lock All Sessions
              </button>
              
              <div className="text-center mt-3">
                <a 
                  href="#" 
                  className="text-xs text-purple-400 hover:text-purple-300 transition-colors"
                  onClick={(e) => {
                    e.preventDefault();
                    // In a real app, this would show advanced security settings
                    alert('Advanced security settings would appear here');
                  }}
                >
                  Advanced Security Settings
                </a>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Clippy Assistant */}
      {isClippyActive && (
        <div className="fixed bottom-20 right-4 w-72 bg-gradient-to-r from-purple-800 to-purple-900 border border-purple-600 rounded-lg p-3 shadow-2xl z-40 backdrop-blur-sm animate-fade-in-up">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 bg-gradient-to-r from-blue-400 to-purple-500 rounded-full flex items-center justify-center animate-bounce flex-shrink-0">
              <Bot className="h-4 w-4 text-white" />
            </div>
            <div className="flex-1 min-w-0">
              <h4 className="text-sm font-medium text-white mb-1">Security Assistant</h4>
              <p className="text-xs text-purple-100 mb-2">
                I'm monitoring your encryption patterns and optimizing security in real-time! I've detected {Math.floor(Math.random() * 5) + 1} potential optimizations.
              </p>
              <div className="flex flex-wrap gap-2">
                <button 
                  className="text-xs bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white px-3 py-1.5 rounded-lg transition-all duration-200 shadow-md flex items-center gap-1"
                  onClick={() => {
                    // In a real app, this would optimize security settings
                    alert('Security settings would be optimized here');
                  }}
                >
                  <Zap className="h-3 w-3" />
                  Optimize Now
                </button>
                <button 
                  className="text-xs bg-purple-700 hover:bg-purple-800 text-white px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1"
                  onClick={() => {
                    // In a real app, this would show security insights
                    alert('Security insights would be shown here');
                  }}
                >
                  <Shield className="h-3 w-3" />
                  View Insights
                </button>
                <button 
                  onClick={() => setIsClippyActive(false)}
                  className="text-xs text-purple-300 hover:text-white transition-colors ml-auto flex items-center gap-1"
                  title="Dismiss"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
              
              {/* Security status indicator */}
              <div className="mt-3 pt-2 border-t border-purple-700">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-purple-300">Security Level</span>
                  <div className="flex items-center gap-1">
                    <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                    <span className="text-green-400 font-medium">Optimal</span>
                  </div>
                </div>
                <div className="w-full bg-gray-800 rounded-full h-1.5 mt-1.5">
                  <div 
                    className="bg-gradient-to-r from-green-400 to-blue-500 h-1.5 rounded-full" 
                    style={{ width: '92%' }}
                  ></div>
                </div>
              </div>
            </div>
          </div>
          
          {/* Clippy's animated thought bubble */}
          <div className="absolute -top-2 -right-2 w-4 h-4 bg-purple-700 transform rotate-45"></div>
        </div>
      )}
    </div>
  );
};

export default ScrambledEggsApp;
