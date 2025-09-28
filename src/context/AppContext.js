import React, { createContext, useState, useContext, useEffect } from 'react';

// Antarctic data center status
const ANTARCTIC_DC = {
  name: 'Aurora Australis',
  location: '78.0626° S, 167.0572° E',
  temperature: '-40°C',
  status: 'operational',
  securityLevel: 'maximum',
  ping: '128ms',
  encryption: 'Quantum-Resistant AES-512',
  jurisdiction: 'Antarctic Treaty System',
  lastSync: new Date().toISOString()
};

const AppContext = createContext();

export const AppProvider = ({ children }) => {
  const [contacts, setContacts] = useState([
    { 
      id: 0, 
      name: 'Alice Johnson', 
      lastMessage: 'File encrypted and sent via Tor 🔐', 
      time: '2:34 PM', 
      unread: 0, 
      status: 'online',
      encryptionLevel: 'AI-Enhanced',
      lastSeen: 'now',
      isTyping: false
    },
    { 
      id: 1, 
      name: 'Bob Wilson', 
      lastMessage: 'Voice call ended - P2P secure', 
      time: '1:22 PM', 
      unread: 3, 
      status: 'offline',
      encryptionLevel: 'Scrambled Eggs Pro',
      lastSeen: '5 minutes ago',
      isTyping: true
    },
    { 
      id: 2, 
      name: 'Charlie Davis', 
      lastMessage: 'Thanks for the anonymous file drop', 
      time: '11:45 AM', 
      unread: 0, 
      status: 'away',
      encryptionLevel: 'AI-Adaptive',
      lastSeen: '1 hour ago',
      isTyping: false
    }
  ]);

  const [messages, setMessages] = useState([
    { id: 1, sender: 'Alice Johnson', content: 'The new AI encryption is incredible!', time: '2:30 PM', isMe: false, encrypted: true, encryptionType: 'AI-Enhanced' },
    { id: 2, sender: 'me', content: 'I know! Clippy helped me optimize the settings.', time: '2:31 PM', isMe: true, encrypted: true, encryptionType: 'Scrambled Eggs Pro' },
  ]);

  const [selectedContact, setSelectedContact] = useState(0);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isSecurityPanelOpen, setIsSecurityPanelOpen] = useState(false);
  const [isClippyActive, setIsClippyActive] = useState(true);
  const [torStatus, setTorStatus] = useState('connected');
  const [networkStatus, setNetworkStatus] = useState({
    tor: 'connected',
    p2p: 'connected',
    peers: 12,
    dataTransferred: '1.4TB',
    lastUpdate: new Date().toISOString()
  });

  const [aiStatus, setAiStatus] = useState({
    learning: true,
    progress: 75,
    lastTrained: '2 minutes ago',
    accuracy: '98.7%',
    active: true,
    antarcticNode: {
      connected: true,
      ...ANTARCTIC_DC,
      lastSync: new Date().toISOString(),
      dataTransferred: '4.2TB',
      secureTunnel: true,
      icePenetration: '2.1km',
      quantumLink: 'entangled',
      zeroTrustScore: 99.99
    }
  });

  // Simulate network status updates
  useEffect(() => {
    const interval = setInterval(() => {
      setNetworkStatus(prev => ({
        ...prev,
        peers: Math.max(5, Math.min(20, prev.peers + Math.floor(Math.random() * 3) - 1)),
        lastUpdate: new Date().toISOString()
      }));
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const refreshNetworkStatus = () => {
    // In a real app, this would fetch the latest network status
    setNetworkStatus(prev => ({
      ...prev,
      lastUpdate: new Date().toISOString()
    }));
  };
  const [theme, setTheme] = useState('dark');
  const [searchQuery, setSearchQuery] = useState('');
  const [notifications, setNotifications] = useState({
    messages: true,
    calls: true,
    securityAlerts: true,
    sound: true,
    vibration: true
  });

  // Toggle Antarctic data center connection
  const toggleAntarcticNode = () => {
    setAiStatus(prev => ({
      ...prev,
      antarcticNode: {
        ...prev.antarcticNode,
        connected: !prev.antarcticNode.connected,
        lastSync: new Date().toISOString()
      }
    }));
  };

  // Toggle theme
  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };

  // Update contact status
  const updateContactStatus = (contactId, status) => {
    setContacts(prev => 
      prev.map(contact => 
        contact.id === contactId ? { ...contact, status } : contact
      )
    );
  };

  // Update notification settings
  const updateNotificationSetting = (setting, value) => {
    setNotifications(prev => ({
      ...prev,
      [setting]: value
    }));
  };

  // Search contacts and messages
  const search = (query) => {
    setSearchQuery(query);
    // Actual search logic would go here
  };

  // Send a new message
  const sendMessage = (content, isFile = false) => {
    const newMessage = {
      id: Date.now(),
      sender: 'me',
      content,
      time: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
      isMe: true,
      encrypted: true,
      encryptionType: 'AI-Enhanced',
      isFile
    };
    
    setMessages(prev => [...prev, newMessage]);
    
    // Simulate response
    if (!isFile) {
      setTimeout(() => {
        const response = {
          id: Date.now() + 1,
          sender: contacts[selectedContact].name,
          content: `Response to: ${content}`,
          time: new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
          isMe: false,
          encrypted: true,
          encryptionType: contacts[selectedContact].encryptionType
        };
        setMessages(prev => [...prev, response]);
      }, 1000);
    }
  };

  // Simulate typing status
  const setTypingStatus = (contactId, isTyping) => {
    setContacts(prev => 
      prev.map(contact => 
        contact.id === contactId ? { ...contact, isTyping } : contact
      )
    );
  };

  return (
    <AppContext.Provider value={{
      contacts,
      messages,
      selectedContact,
      setSelectedContact,
      isMenuOpen,
      setIsMenuOpen,
      isSecurityPanelOpen,
      setIsSecurityPanelOpen,
      isClippyActive,
      setIsClippyActive,
      torStatus,
      setTorStatus,
      setAiStatus,
      theme,
      toggleTheme,
      searchQuery,
      search,
      sendMessage,
      setTypingStatus,
      updateContactStatus,
      antarcticDC: ANTARCTIC_DC,
      networkStatus,
      refreshNetworkStatus
    }>
      {children}
    </AppContext.Provider>
  );
};
export const useAppContext = () => {
  return useContext(AppContext);
};
