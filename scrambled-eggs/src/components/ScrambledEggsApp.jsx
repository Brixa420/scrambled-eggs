import React, { useState, useRef, useEffect } from 'react';
import { 
  Send, Phone, Video, Paperclip, Shield, Settings, Search, 
  MoreVertical, Lock, Users, Bell, Eye, EyeOff, CheckCircle, 
  AlertTriangle, Minimize2, X, Plus, Clock, Globe, Folder, 
  Key, Bot, Menu, Home, MessageSquare, FileText, Network, 
  Brain, Download, Upload, Zap, Activity 
} from 'lucide-react';

const ScrambledEggsApp = () => {
  const [selectedChat, setSelectedChat] = useState(0);
  const [message, setMessage] = useState('');
  const [isSecurityPanelOpen, setIsSecurityPanelOpen] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [activeView, setActiveView] = useState('chat');
  const [isClippyActive, setIsClippyActive] = useState(true);
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
    }
  ];

  const messages = [
    { id: 1, sender: 'Alice Johnson', content: 'The new AI encryption is incredible!', time: '2:30 PM', isMe: false, encrypted: true, encryptionType: 'AI-Enhanced' },
    { id: 2, sender: 'me', content: 'I know! The autonomous learning is amazing.', time: '2:31 PM', isMe: true, encrypted: true, encryptionType: 'Scrambled Eggs Pro' },
  ];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSendMessage = () => {
    if (message.trim()) {
      console.log('Message sent:', message);
      setMessage('');
    }
  };

  return (
    <div className="h-screen bg-black text-white flex overflow-hidden relative">
      {/* Sidebar */}
      <div className="w-80 bg-gradient-to-b from-purple-900 to-black border-r border-purple-800 flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-purple-800">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-r from-purple-400 to-purple-600 rounded-lg flex items-center justify-center">
                <span className="text-black font-bold">🥚</span>
              </div>
              <h1 className="text-xl font-bold text-white">Scrambled Eggs</h1>
            </div>
            <div className="flex items-center gap-2">
              <button 
                onClick={() => setIsMenuOpen(!isMenuOpen)}
                className="p-2 hover:bg-purple-800 rounded-lg"
              >
                <Menu className="h-5 w-5 text-purple-300" />
              </button>
              <button 
                onClick={() => setIsSecurityPanelOpen(!isSecurityPanelOpen)}
                className="p-2 hover:bg-purple-800 rounded-lg"
              >
                <Shield className="h-5 w-5 text-purple-300" />
              </button>
            </div>
          </div>
        </div>

        {/* Rest of your component JSX */}
        
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        {/* Chat Header */}
        <div className="p-4 border-b border-purple-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-r from-purple-500 to-purple-700 rounded-full flex items-center justify-center">
              <span className="text-white font-bold text-sm">
                {contacts[selectedChat].name.split(' ').map(n => n[0]).join('')}
              </span>
            </div>
            <div>
              <h2 className="font-semibold text-white">{contacts[selectedChat].name}</h2>
              <div className="flex items-center gap-1 text-sm text-purple-400">
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
                <span>{contacts[selectedChat].status}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((msg) => (
            <div key={msg.id} className={lex }>
              <div className={max-w-xs lg:max-w-md px-4 py-2 rounded-2xl }>
                <p className="text-sm">{msg.content}</p>
                <div className="flex items-center justify-between mt-1 text-xs text-purple-200">
                  <span>{msg.time}</span>
                  {msg.encrypted && <span>🔒 {msg.encryptionType}</span>}
                </div>
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Message Input */}
        <div className="p-4 border-t border-purple-800">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
              placeholder="Type a message..."
              className="flex-1 bg-black bg-opacity-50 border border-purple-700 rounded-lg py-2 px-4 text-white focus:outline-none focus:border-purple-500"
            />
            <button 
              onClick={handleSendMessage}
              className="bg-gradient-to-r from-purple-600 to-purple-800 text-white p-2 rounded-lg"
            >
              <Send className="h-5 w-5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScrambledEggsApp;
