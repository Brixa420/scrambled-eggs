import React, { useState, useEffect, useCallback } from 'react';
import ScrambledEggsApp from './components/ScrambledEggsApp';
import AIChat from './components/AIChat';
import P2PChatInterface from './components/P2PChatInterface';
import Clippy from './components/Clippy/Clippy';
import { AppProvider } from './context/AppContext';
import './App.css';

function AppContent() {
  const [showAIChat, setShowAIChat] = useState(false);
  const [showP2PChat, setShowP2PChat] = useState(false);
  const [isClippyVisible, setIsClippyVisible] = useState(true);

  const toggleAIChat = () => {
    setShowAIChat(!showAIChat);
  };

  const toggleP2PChat = () => {
    setShowP2PChat(!showP2PChat);
  };
  
  const toggleClippy = () => {
    setIsClippyVisible(!isClippyVisible);
  };

  // Add keyboard shortcuts
  const handleKeyDown = useCallback((e) => {
    // Toggle P2P chat (Ctrl+Alt+P)
    if (e.ctrlKey && e.altKey) {
      switch (e.key.toLowerCase()) {
        case 'p':
          e.preventDefault();
          toggleP2PChat();
          break;
        case 'a':
          e.preventDefault();
          toggleAIChat();
          break;
        case 'c':
          e.preventDefault();
          toggleClippy();
          break;
        default:
          break;
      }
    }
  }, [toggleP2PChat, toggleAIChat, toggleClippy]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return (
    <div className="App">
      <ScrambledEggsApp 
        onToggleClippy={toggleClippy} 
        onToggleAIChat={toggleAIChat}
        onToggleP2PChat={toggleP2PChat}
      />
      
      {/* Floating Controls */}
      <div className="floating-controls">
        <button 
          onClick={toggleClippy} 
          className={`floating-button ${isClippyVisible ? 'active' : ''}`}
          title="Toggle Clippy (Ctrl+Alt+C)"
        >
          <span role="img" aria-label="Clippy">📎</span>
        </button>
        
        <button 
          onClick={toggleAIChat} 
          className={`floating-button ${showAIChat ? 'active' : ''}`}
          title="AI Chat (Ctrl+Alt+A)"
        >
          <span role="img" aria-label="AI Chat">🤖</span>
        </button>
        
        <button 
          onClick={toggleP2PChat} 
          className={`floating-button ${showP2PChat ? 'active' : ''}`}
          title="P2P Chat (Ctrl+Alt+P)"
        >
          <span role="img" aria-label="P2P Chat">🌐</span>
        </button>
      </div>
      
      {/* Clippy Component */}
      {isClippyVisible && <Clippy />}
      
      {/* Other UI Components */}
      {showAIChat && <AIChat onClose={toggleAIChat} />}
      {showP2PChat && <P2PChatInterface onClose={toggleP2PChat} />}
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
