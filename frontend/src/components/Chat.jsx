import React, { useState, useEffect, useRef, useCallback } from 'react';
import { v4 as uuidv4 } from 'uuid';
import io from 'socket.io-client';
import { formatDistanceToNow } from 'date-fns';

const Chat = ({ userId, roomId = 'default' }) => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [typingUsers, setTypingUsers] = useState({});
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isLLMEnabled, setIsLLMEnabled] = useState(true);
  
  const messagesEndRef = useRef(null);
  const socketRef = useRef(null);
  const typingTimeoutRef = useRef(null);

  // Initialize socket connection
  useEffect(() => {
    const socket = io(process.env.REACT_APP_API_URL || 'http://localhost:5000', {
      withCredentials: true,
      transports: ['websocket'],
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socketRef.current = socket;

    // Connection events
    socket.on('connect', () => {
      console.log('Connected to WebSocket');
      setIsConnected(true);
      setError(null);
      
      // Join the room
      socket.emit('join_room', { room: roomId });
    });

    socket.on('disconnect', () => {
      console.log('Disconnected from WebSocket');
      setIsConnected(false);
    });

    socket.on('connect_error', (error) => {
      console.error('Connection error:', error);
      setError('Failed to connect to the chat server. Please try again later.');
    });

    // Message events
    socket.on('new_message', (message) => {
      console.log('New message:', message);
      setMessages(prev => [...prev, { ...message, status: 'delivered' }]);
      scrollToBottom();
    });

    socket.on('message_status', ({ message_id, status, message }) => {
      console.log(`Message ${message_id} status:`, status, message);
      setMessages(prev => 
        prev.map(msg => 
          msg.id === message_id ? { ...msg, status, error: message } : msg
        )
      );
    });

    socket.on('user_typing', ({ user_id, is_typing }) => {
      setTypingUsers(prev => ({
        ...prev,
        [user_id]: is_typing ? Date.now() : null
      }));
    });

    socket.on('error', (error) => {
      console.error('Socket error:', error);
      setError(error.message || 'An error occurred');
    });

    // Cleanup on unmount
    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('new_message');
      socket.off('message_status');
      socket.off('user_typing');
      socket.off('error');
      socket.disconnect();
    };
  }, [roomId]);

  // Auto-scroll to bottom when messages change
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  // Handle typing indicator
  const handleInputChange = (e) => {
    const value = e.target.value;
    setInput(value);
    
    // Notify others that user is typing
    if (!isTyping) {
      socketRef.current.emit('typing', {
        room: roomId,
        is_typing: true
      });
      setIsTyping(true);
    }

    // Clear the previous timeout
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }

    // Set a timeout to stop the typing indicator after 2 seconds of inactivity
    typingTimeoutRef.current = setTimeout(() => {
      socketRef.current.emit('typing', {
        room: roomId,
        is_typing: false
      });
      setIsTyping(false);
    }, 2000);
  };

  // Handle sending a message
  const handleSendMessage = async (e) => {
    e.preventDefault();
    
    const messageContent = input.trim();
    if (!messageContent || !socketRef.current || !isConnected) {
      return;
    }

    const messageId = uuidv4();
    const tempMessage = {
      id: messageId,
      user_id: userId,
      content: messageContent,
      timestamp: new Date().toISOString(),
      room_id: roomId,
      status: 'sending'
    };

    // Add temporary message to UI
    setMessages(prev => [...prev, tempMessage]);
    setInput('');
    scrollToBottom();
    
    try {
      setIsLoading(true);
      
      // Send the message to the server
      socketRef.current.emit('send_message', {
        message_id: messageId,
        content: messageContent,
        room_id: roomId,
        requires_llm: isLLMEnabled
      });
      
    } catch (error) {
      console.error('Error sending message:', error);
      setError('Failed to send message. Please try again.');
      
      // Update message status to failed
      setMessages(prev => 
        prev.map(msg => 
          msg.id === messageId 
            ? { ...msg, status: 'error', error: 'Failed to send' } 
            : msg
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  // Format typing indicators
  const getTypingIndicator = () => {
    const typingUserIds = Object.entries(typingUsers)
      .filter(([_, timestamp]) => timestamp && Date.now() - timestamp < 2000)
      .map(([id]) => id);

    if (typingUserIds.length === 0) return null;
    
    const typingNames = typingUserIds.join(', ');
    const isAre = typingUserIds.length > 1 ? 'are' : 'is';
    
    return (
      <div className="typing-indicator">
        {typingNames} {isAre} typing...
      </div>
    );
  };

  // Format message timestamp
  const formatTimestamp = (isoString) => {
    return formatDistanceToNow(new Date(isoString), { addSuffix: true });
  };

  // Render message status icon
  const renderStatusIcon = (status) => {
    switch (status) {
      case 'sending':
        return <span className="text-yellow-500 text-xs">Sending...</span>;
      case 'delivered':
        return <span className="text-green-500 text-xs">✓</span>;
      case 'error':
        return <span className="text-red-500 text-xs">✗</span>;
      default:
        return null;
    }
  };

  return (
    <div className="flex flex-col h-full bg-gray-100 dark:bg-gray-900">
      {/* Header */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
          Chat Room: {roomId}
        </h2>
        <div className="flex items-center mt-1">
          <span className={`h-2 w-2 rounded-full mr-2 ${isConnected ? 'bg-green-500' : 'bg-red-500'}`}></span>
          <span className="text-sm text-gray-600 dark:text-gray-400">
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
          
          <label className="ml-4 flex items-center cursor-pointer">
            <div className="relative">
              <input 
                type="checkbox" 
                className="sr-only" 
                checked={isLLMEnabled}
                onChange={() => setIsLLMEnabled(!isLLMEnabled)}
              />
              <div className={`block w-10 h-6 rounded-full ${isLLMEnabled ? 'bg-blue-600' : 'bg-gray-400'}`}></div>
              <div className={`dot absolute left-1 top-1 bg-white w-4 h-4 rounded-full transition ${isLLMEnabled ? 'transform translate-x-4' : ''}`}></div>
            </div>
            <div className="ml-2 text-sm text-gray-700 dark:text-gray-300">
              AI Assistant {isLLMEnabled ? 'Enabled' : 'Disabled'}
            </div>
          </label>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 p-4 overflow-y-auto">
        {error && (
          <div className="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-4" role="alert">
            <p>{error}</p>
          </div>
        )}

        <div className="space-y-4">
          {messages.map((message) => (
            <div 
              key={message.id} 
              className={`flex ${message.user_id === userId ? 'justify-end' : 'justify-start'}`}
            >
              <div 
                className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                  message.user_id === userId 
                    ? 'bg-blue-500 text-white' 
                    : message.user_id === 'llm'
                      ? 'bg-green-500 text-white'
                      : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
                }`}
              >
                {message.user_id !== userId && message.user_id !== 'llm' && (
                  <div className="font-semibold text-xs mb-1">
                    User {message.user_id}
                  </div>
                )}
                {message.user_id === 'llm' && (
                  <div className="font-semibold text-xs mb-1">
                    AI Assistant
                  </div>
                )}
                <p className="whitespace-pre-wrap break-words">{message.content}</p>
                <div className="flex justify-between items-center mt-1">
                  <span className="text-xs opacity-75">
                    {formatTimestamp(message.timestamp)}
                  </span>
                  {renderStatusIcon(message.status)}
                </div>
                {message.error && (
                  <div className="text-xs text-red-200 mt-1">
                    {message.error}
                  </div>
                )}
              </div>
            </div>
          ))}
          <div ref={messagesEndRef} />
        </div>
        
        {/* Typing indicators */}
        <div className="mt-2">
          {getTypingIndicator()}
        </div>
      </div>

      {/* Input area */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
        <form onSubmit={handleSendMessage} className="flex space-x-2">
          <input
            type="text"
            value={input}
            onChange={handleInputChange}
            placeholder="Type a message..."
            className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
            disabled={!isConnected || isLoading}
          />
          <button
            type="submit"
            disabled={!input.trim() || !isConnected || isLoading}
            className="px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <span className="flex items-center">
                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Sending...
              </span>
            ) : 'Send'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default Chat;
