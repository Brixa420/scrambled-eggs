import React, { useState, useEffect, useRef, useCallback, useContext } from 'react';
import { Send, Mic, Paperclip, Check, Clock, AlertCircle, X } from 'lucide-react';
import { AppContext } from '../context/AppContext';

const MessageStatus = ({ status }) => {
  if (status === 'sending') return <Clock size={14} className="text-gray-400" />;
  if (status === 'delivered') return <Check size={14} className="text-blue-500" />;
  if (status === 'read') return <Check size={14} className="text-blue-500" />;
  if (status === 'failed') return <AlertCircle size={14} className="text-red-500" />;
  return null;
};

const P2PChat = ({ peerId, onClose }) => {
  const { p2p } = useContext(AppContext);
  const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [isTyping, setIsTyping] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const messagesEndRef = useRef(null);
  const typingTimeout = useRef(null);

  // Connect to peer when component mounts
  useEffect(() => {
    if (peerId && p2p.connectToPeer) {
      setConnectionStatus('connecting');
      p2p.connectToPeer(peerId)
        .then(() => setConnectionStatus('connected'))
        .catch(() => setConnectionStatus('failed'));
    }

    return () => {
      if (typingTimeout.current) {
        clearTimeout(typingTimeout.current);
      }
    };
  }, [peerId, p2p]);

  // Handle incoming messages
  useEffect(() => {
    if (!p2p.onMessage) return;

    const handleMessage = (data, senderId) => {
      if (senderId !== peerId) return;
      
      setMessages(prev => [...prev, {
        ...data,
        isMe: false,
        status: 'delivered'
      }]);
    };

    p2p.onMessage = handleMessage;
    return () => {
      p2p.onMessage = null;
    };
  }, [peerId, p2p]);

  // Handle typing indicators
  useEffect(() => {
    if (!p2p.setTyping) return;

    const handleTyping = (isTyping, senderId) => {
      if (senderId !== peerId) return;
      setIsTyping(isTyping);
    };

    p2p.setTyping = handleTyping;
    return () => {
      p2p.setTyping = null;
    };
  }, [peerId, p2p]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Handle sending a message
  const handleSendMessage = useCallback(async () => {
    if (!message.trim() || !p2p.sendMessage) return;

    const messageId = Date.now().toString();
    const newMessage = {
      id: messageId,
      content: message,
      timestamp: new Date().toISOString(),
      status: 'sending'
    };

    // Add to local messages immediately for instant feedback
    setMessages(prev => [...prev, { ...newMessage, isMe: true }]);
    
    try {
      // Send the message via P2P
      await p2p.sendMessage(peerId, message);
      
      // Update message status to delivered
      setMessages(prev =>
        prev.map(msg =>
          msg.id === messageId ? { ...msg, status: 'delivered' } : msg
        )
      );
    } catch (error) {
      console.error('Failed to send message:', error);
      // Update message status to failed
      setMessages(prev =>
        prev.map(msg =>
          msg.id === messageId ? { ...msg, status: 'failed' } : msg
        )
      );
    }

    setMessage('');
    p2p.setTyping?.(false, peerId);
  }, [message, p2p, peerId]);

  // Handle typing indicator
  const handleInputChange = (e) => {
    const text = e.target.value;
    setMessage(text);
    
    // Notify peer about typing status
    if (!typingTimeout.current && text) {
      p2p.setTyping?.(true, peerId);
    }
    
    // Clear any existing timeout
    if (typingTimeout.current) {
      clearTimeout(typingTimeout.current);
    }
    
    // Set a new timeout to reset typing status
    typingTimeout.current = setTimeout(() => {
      p2p.setTyping?.(false, peerId);
      typingTimeout.current = null;
    }, 2000);
  };

  // Handle key press for sending message on Enter
  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Format message timestamp
  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="flex flex-col h-full bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <div className="flex items-center space-x-3">
          <div className={`w-3 h-3 rounded-full ${
            connectionStatus === 'connected' ? 'bg-green-500' : 
            connectionStatus === 'connecting' ? 'bg-yellow-500' : 'bg-red-500'
          }`} />
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            {peerId.slice(0, 8)}...{peerId.slice(-4)}
          </h2>
          {isTyping && (
            <span className="text-sm text-gray-500 dark:text-gray-400">typing...</span>
          )}
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700"
          aria-label="Close chat"
        >
          <X className="w-5 h-5 text-gray-500 dark:text-gray-400" />
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex ${msg.isMe ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                msg.isMe
                  ? 'bg-blue-500 text-white rounded-br-none'
                  : 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-bl-none'
              }`}
            >
              <p className="break-words">{msg.content}</p>
              <div className="flex items-center justify-end mt-1 space-x-1">
                <span className="text-xs opacity-70">
                  {formatTime(msg.timestamp)}
                </span>
                {msg.isMe && <MessageStatus status={msg.status} />}
              </div>
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input area */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <div className="flex items-center space-x-2">
          <button className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">
            <Paperclip className="w-5 h-5" />
          </button>
          <div className="relative flex-1">
            <textarea
              value={message}
              onChange={handleInputChange}
              onKeyPress={handleKeyPress}
              placeholder="Type a message..."
              className="w-full px-4 py-2 pr-12 text-gray-900 bg-gray-100 border border-gray-300 rounded-full focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600 dark:text-white dark:placeholder-gray-400"
              rows="1"
            />
            <button className="absolute right-2 top-1/2 transform -translate-y-1/2 p-1 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">
              <Mic className="w-5 h-5" />
            </button>
          </div>
          <button
            onClick={handleSendMessage}
            disabled={!message.trim()}
            className="p-2 text-white bg-blue-500 rounded-full hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed"
            aria-label="Send message"
          >
            <Send className="w-5 h-5" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default P2PChat;
