import React, { useState, useEffect, useRef, useContext } from 'react';
import { Plus, MessageSquare, X } from 'lucide-react';
import P2PChat from './P2PChat';
import { AppContext } from '../context/AppContext';

const P2PChatInterface = () => {
  const { p2p } = useContext(AppContext);
  const [activeChats, setActiveChats] = useState([]);
  const [showChatList, setShowChatList] = useState(false);
  const [peerIdInput, setPeerIdInput] = useState('');
  const [showPeerInput, setShowPeerInput] = useState(false);
  const inputRef = useRef(null);

  // Focus input when showing peer ID input
  useEffect(() => {
    if (showPeerInput && inputRef.current) {
      inputRef.current.focus();
    }
  }, [showPeerInput]);

  // Open a new chat with a peer
  const openChat = (peerId) => {
    if (!peerId || activeChats.includes(peerId)) return;
    setActiveChats(prev => [...prev, peerId]);
    setShowPeerInput(false);
    setPeerIdInput('');
  };

  // Close a chat
  const closeChat = (peerId) => {
    setActiveChats(prev => prev.filter(id => id !== peerId));
  };

  // Toggle chat list visibility
  const toggleChatList = () => {
    setShowChatList(prev => !prev);
  };

  // Handle starting a new chat
  const handleNewChat = () => {
    if (peerIdInput.trim()) {
      openChat(peerIdInput.trim());
    }
  };

  // Handle Enter key press in peer ID input
  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleNewChat();
    }
  };

  // Get online peers (excluding self and already opened chats)
  const availablePeers = (p2p.peers || []).filter(
    peerId => peerId !== p2p.peerId && !activeChats.includes(peerId)
  );

  return (
    <div className="fixed bottom-0 right-0 z-50 flex flex-col items-end mr-4 mb-4 space-y-2">
      {/* Active Chats */}
      <div className="flex space-x-2 overflow-x-auto max-w-[calc(100vw-2rem)]">
        {activeChats.map(peerId => (
          <div
            key={peerId}
            className="w-80 h-[500px] bg-white dark:bg-gray-800 rounded-lg shadow-lg overflow-hidden flex flex-col"
          >
            <P2PChat peerId={peerId} onClose={() => closeChat(peerId)} />
          </div>
        ))}
      </div>

      {/* Chat Toggle Button */}
      <div className="flex items-center space-x-2">
        {/* Chat List Toggle */}
        <button
          onClick={toggleChatList}
          className="p-3 text-white bg-blue-500 rounded-full shadow-lg hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50"
          aria-label="Toggle chat"
        >
          <MessageSquare className="w-6 h-6" />
        </button>

        {/* New Chat Button */}
        <button
          onClick={() => setShowPeerInput(!showPeerInput)}
          className="p-3 text-white bg-green-500 rounded-full shadow-lg hover:bg-green-600 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-50"
          aria-label="New chat"
        >
          <Plus className="w-6 h-6" />
        </button>
      </div>

      {/* Peer ID Input */}
      {showPeerInput && (
        <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg w-80">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">New Chat</h3>
            <button
              onClick={() => setShowPeerInput(false)}
              className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="flex space-x-2">
            <input
              ref={inputRef}
              type="text"
              value={peerIdInput}
              onChange={(e) => setPeerIdInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Enter peer ID"
              className="flex-1 px-3 py-2 text-gray-900 bg-gray-100 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white dark:placeholder-gray-400"
            />
            <button
              onClick={handleNewChat}
              disabled={!peerIdInput.trim()}
              className="px-4 py-2 text-white bg-blue-500 rounded-md hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Start
            </button>
          </div>
        </div>
      )}

      {/* Chat List */}
      {showChatList && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg w-80 overflow-hidden">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Online Peers</h3>
              <button
                onClick={toggleChatList}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>
          <div className="max-h-60 overflow-y-auto">
            {availablePeers.length > 0 ? (
              availablePeers.map((peerId) => (
                <button
                  key={peerId}
                  onClick={() => {
                    openChat(peerId);
                    setShowChatList(false);
                  }}
                  className="w-full px-4 py-3 text-left hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                >
                  <div className="flex items-center">
                    <div className="w-2 h-2 rounded-full bg-green-500 mr-2"></div>
                    <span className="text-gray-900 dark:text-white truncate">
                      {peerId.slice(0, 8)}...{peerId.slice(-4)}
                    </span>
                  </div>
                </button>
              ))
            ) : (
              <div className="p-4 text-center text-gray-500 dark:text-gray-400">
                No other peers online
              </div>
            )}
          </div>
          <div className="p-4 border-t border-gray-200 dark:border-gray-700 text-center">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Your ID: <span className="font-mono text-xs">{p2p.peerId}</span>
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default P2PChatInterface;
