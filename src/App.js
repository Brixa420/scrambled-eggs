import React, { useState, useEffect } from 'react';
import ScrambledEggsApp from './components/ScrambledEggsApp';
import AnarchistClippy from './components/AnarchistClippy';
import AIChat from './components/AIChat';
import P2PChatInterface from './components/P2PChatInterface';
import { AppProvider } from './context/AppContext';
import './App.css';

function AppContent() {
  const [showClippy, setShowClippy] = useState(false);
  const [showAIChat, setShowAIChat] = useState(false);
  const [showP2PChat, setShowP2PChat] = useState(false);

  const toggleClippy = () => {
    setShowClippy(!showClippy);
  };

  const toggleAIChat = () => {
    setShowAIChat(!showAIChat);
  };

  const toggleP2PChat = () => {
    setShowP2PChat(!showP2PChat);
  };

  // Add keyboard shortcut for P2P chat (Ctrl+Alt+P)
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.ctrlKey && e.altKey && e.key.toLowerCase() === 'p') {
        e.preventDefault();
        toggleP2PChat();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className="App">
      <ScrambledEggsApp 
        onToggleClippy={toggleClippy} 
        onToggleAIChat={toggleAIChat}
        onToggleP2PChat={toggleP2PChat}
      />
      {showClippy && <AnarchistClippy onClose={() => setShowClippy(false)} />}
      {showAIChat && <AIChat onClose={() => setShowAIChat(false)} />}
      {showP2PChat && <P2PChatInterface />}
    </div>
  );
}

function App() {
  return (
    <AppProvider>
      <AppContent />
    </AppProvider>
  );
}

export default App;
