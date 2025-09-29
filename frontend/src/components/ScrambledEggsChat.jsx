import React, { useState, useRef, useEffect } from 'react';
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

const ScrambledEggsChat = () => {
  const [selectedChat, setSelectedChat] = useState(0);
  const [message, setMessage] = useState('');
  const [isSecurityPanelOpen, setIsSecurityPanelOpen] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [activeView, setActiveView] = useState('chat');
  const [isClippyActive, setIsClippyActive] = useState(true);
  const [torStatus, setTorStatus] = useState('connected');
  const [aiEncryptionStatus, setAiEncryptionStatus] = useState('learning');
  const messagesEndRef = useRef(null);

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
      setMessage('');
    }
  };

  const MainMenu = () => (
    <div className="absolute top-0 left-0 w-80 h-full bg-gradient-to-b from-purple-900 via-purple-950 to-black border-r border-purple-700 shadow-2xl z-50 backdrop-blur-sm">
      <div className="p-4 border-b border-purple-800">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold bg-gradient-to-r from-purple-300 to-purple-500 bg-clip-text text-transparent">Menu</h2>
          <button 
            onClick={() => setIsMenuOpen(false)}
            className="p-2 hover:bg-purple-800 rounded-lg transition-colors"
          >
            <X className="h-5 w-5 text-purple-300" />
          </button>
        </div>
      </div>
      
      <div className="p-4 space-y-2">
        {/* Main Features */}
        <div className="mb-6">
          <h3 className="text-sm text-purple-400 mb-3 font-semibold">COMMUNICATION</h3>
          <button 
            onClick={() => {setActiveView('chat'); setIsMenuOpen(false);}}
            className={`w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 ${activeView === 'chat' ? 'bg-purple-800 text-white' : 'hover:bg-purple-900 text-purple-200'}` }
          >
            <MessageSquare className="h-5 w-5" />
            <div>
              <div className="font-medium">P2P Chat</div>
              <div className="text-xs text-purple-400">Secure messaging</div>
            </div>
          </button>
          
          <button 
            onClick={() => {setActiveView('voice'); setIsMenuOpen(false);}}
            className="w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 hover:bg-purple-900 text-purple-200 mt-2"
          >
            <Phone className="h-5 w-5" />
            <div>
              <div className="font-medium">P2P Voice & Video</div>
              <div className="text-xs text-purple-400">Encrypted calls</div>
            </div>
          </button>
        </div>

        {/* Privacy & Security */}
        <div className="mb-6">
          <h3 className="text-sm text-purple-400 mb-3 font-semibold">PRIVACY & SECURITY</h3>
          <button 
            onClick={() => {setActiveView('tor'); setIsMenuOpen(false);}}
            className="w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 hover:bg-purple-900 text-purple-200"
          >
            <Globe className="h-5 w-5" />
            <div>
              <div className="font-medium">Tor Browser</div>
              <div className="text-xs text-purple-400">Anonymous browsing</div>
            </div>
          </button>
          
          <button 
            onClick={() => {setActiveView('nodes'); setIsMenuOpen(false);}}
            className="w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 hover:bg-purple-900 text-purple-200 mt-2"
          >
            <Network className="h-5 w-5" />
            <div>
              <div className="font-medium">Tor Nodes</div>
              <div className="text-xs text-purple-400">Network management</div>
            </div>
          </button>
        </div>

        {/* File Management */}
        <div className="mb-6">
          <h3 className="text-sm text-purple-400 mb-3 font-semibold">FILE MANAGEMENT</h3>
          <button 
            onClick={() => {setActiveView('files'); setIsMenuOpen(false);}}
            className="w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 hover:bg-purple-900 text-purple-200"
          >
            <Folder className="h-5 w-5" />
            <div>
              <div className="font-medium">File Sharing</div>
              <div className="text-xs text-purple-400">P2P file transfer</div>
            </div>
          </button>
          
          <button 
            onClick={() => {setActiveView('encryption'); setIsMenuOpen(false);}}
            className="w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 hover:bg-purple-900 text-purple-200 mt-2"
          >
            <Key className="h-5 w-5" />
            <div>
              <div className="font-medium">File Encryption</div>
              <div className="text-xs text-purple-400">Encrypt/Decrypt files</div>
            </div>
          </button>
        </div>

        {/* AI & Automation */}
        <div className="mb-6">
          <h3 className="text-sm text-purple-400 mb-3 font-semibold">AI & AUTOMATION</h3>
          <button 
            onClick={() => {setActiveView('clippy'); setIsMenuOpen(false);}}
            className="w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 hover:bg-purple-900 text-purple-200"
          >
            <Bot className="h-5 w-5" />
            <div>
              <div className="font-medium">Clippy AI Assistant</div>
              <div className="text-xs text-purple-400">Smart help & automation</div>
            </div>
          </button>
          
          <button 
            onClick={() => {setActiveView('scrambled'); setIsMenuOpen(false);}}
            className="w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 hover:bg-purple-900 text-purple-200 mt-2"
          >
            <Brain className="h-5 w-5" />
            <div>
              <div className="font-medium">Scrambled Eggs AI</div>
              <div className="text-xs text-purple-400">Autonomous encryption</div>
            </div>
          </button>
        </div>

        {/* Settings */}
        <button 
          onClick={() => {setActiveView('settings'); setIsMenuOpen(false);}}
          className="w-full p-3 rounded-lg text-left flex items-center gap-3 transition-all duration-300 hover:bg-purple-900 text-purple-200"
        >
          <Settings className="h-5 w-5" />
          <div>
            <div className="font-medium">Settings</div>
            <div className="text-xs text-purple-400">App configuration</div>
          </div>
        </button>
      </div>
      
      {/* Status Panel */}
      <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-purple-800 bg-gradient-to-r from-purple-900 to-black">
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-purple-400">Tor Status</span>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              <span className="text-green-400">Connected</span>
            </div>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-purple-400">AI Encryption</span>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
              <span className="text-blue-400">Learning</span>
            </div>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-purple-400">Clippy</span>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
              <span className="text-purple-400">Active</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const SecurityPanel = () => (
    <div className="absolute top-16 right-4 w-80 bg-gradient-to-b from-purple-900 to-black border border-purple-700 rounded-lg shadow-2xl p-4 z-50 backdrop-blur-sm">
      <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
        <Shield className="h-5 w-5 text-purple-300" />
        Scrambled Eggs Security ✨
      </h3>
      
      <div className="space-y-3">
        <div className="flex items-center justify-between p-3 bg-black bg-opacity-30 rounded border border-purple-800">
          <span className="text-purple-200">AI Encryption</span>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
            <span className="text-blue-400 text-sm">Adaptive Learning 🧠</span>
          </div>
        </div>
        
        <div className="flex items-center justify-between p-3 bg-black bg-opacity-30 rounded border border-purple-800">
          <span className="text-purple-200">Base Encryption</span>
          <span className="text-purple-400 text-sm">AES-256-GCM ⭐</span>
        </div>
        
        <div className="flex items-center justify-between p-3 bg-black bg-opacity-30 rounded border border-purple-800">
          <span className="text-purple-200">Tor Integration</span>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            <span className="text-green-400 text-sm">Active</span>
          </div>
        </div>
        
        <div className="flex items-center justify-between p-3 bg-black bg-opacity-30 rounded border border-purple-800">
          <span className="text-purple-200">P2P Network</span>
          <span className="text-purple-300">🌟</span>
        </div>
        
        <div className="flex items-center justify-between p-3 bg-black bg-opacity-30 rounded border border-purple-800">
          <span className="text-purple-200">Autonomous Mode</span>
          <span className="text-blue-400 text-sm">Enabled ✦</span>
        </div>
      </div>
      
      <button className="w-full mt-4 bg-gradient-to-r from-purple-600 to-purple-800 hover:from-purple-500 hover:to-purple-700 text-white py-2 px-4 rounded transition-all duration-300 shadow-lg">
        AI Security Reset 🚨
      </button>
    </div>
  );

  const ClippyAssistant = () => (
    isClippyActive && (
      <div className="fixed bottom-20 right-4 w-64 bg-gradient-to-r from-purple-800 to-purple-900 border border-purple-600 rounded-lg p-3 shadow-2xl z-40 backdrop-blur-sm">
        <div className="flex items-start gap-3">
          <div className="w-8 h-8 bg-gradient-to-r from-blue-400 to-purple-500 rounded-full flex items-center justify-center animate-bounce">
            <Bot className="h-4 w-4 text-white" />
          </div>
          <div className="flex-1">
            <p className="text-sm text-white mb-2">
              Hi! I'm Clippy, your AI security assistant. I'm monitoring your encryption patterns and optimizing security in real-time! 🤖✨
            </p>
            <div className="flex gap-2">
              <button className="text-xs bg-purple-600 hover:bg-purple-700 text-white px-2 py-1 rounded transition-colors">
                Optimize
              </button>
              <button 
                onClick={() => setIsClippyActive(false)}
                className="text-xs text-purple-400 hover:text-white transition-colors"
              >
                Hide
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  );

  return (
    <div className="h-screen bg-black text-white flex overflow-hidden relative">
      {/* Animated stars background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-10 left-10 text-purple-300 opacity-60 animate-pulse">✦</div>
        <div className="absolute top-20 right-20 text-purple-400 opacity-40 animate-bounce">🌙</div>
        <div className="absolute top-32 left-1/3 text-purple-200 opacity-50">✨</div>
        <div className="absolute top-40 right-1/4 text-purple-300 opacity-30 animate-pulse">⭐</div>
        <div className="absolute top-60 left-20 text-purple-400 opacity-60">🌟</div>
        <div className="absolute bottom-40 right-10 text-purple-300 opacity-40 animate-bounce">✦</div>
        <div className="absolute bottom-20 left-1/4 text-purple-200 opacity-50 animate-pulse">🌙</div>
        <div className="absolute bottom-32 right-1/3 text-purple-400 opacity-30">✨</div>
        <div className="absolute top-1/2 left-10 text-purple-300 opacity-40 animate-pulse">⭐</div>
        <div className="absolute top-1/3 right-10 text-purple-400 opacity-50">🌟</div>
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
              >
                <Shield className="h-5 w-5 text-purple-300" />
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

      {/* Menu Overlay */}
      {isMenuOpen && <MainMenu />}

      {/* Security Panel */}
      {isSecurityPanelOpen && <SecurityPanel />}

      {/* Clippy Assistant */}
      <ClippyAssistant />
    </div>
  );
};

export default ScrambledEggsChat;
