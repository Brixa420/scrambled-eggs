import React, { useState, useRef, useEffect } from 'react';
import { useAIChat } from '../../hooks/useAIChat';
import { 
  Send, 
  X, 
  Bot, 
  User, 
  Moon, 
  Sun, 
  Trash2,
  Loader2,
  Settings,
  Menu,
  MessageSquare
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useTheme } from '../../context/ThemeContext';
import './AIChat.css';

const Message = ({ message, theme }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className={`message ${message.role} ${theme}`}
  >
    <div className="message-avatar">
      {message.role === 'assistant' ? (
        <div className="ai-avatar">
          <Bot size={18} />
        </div>
      ) : (
        <div className="user-avatar">
          <User size={18} />
        </div>
      )}
    </div>
    <div className="message-content">
      {message.content || (
        <div className="typing-indicator">
          <span></span>
          <span></span>
          <span></span>
        </div>
      )}
    </div>
  </motion.div>
);

const AIChat = ({ onClose }) => {
  const { theme, toggleTheme } = useTheme();
  const {
    messages,
    input,
    setInput,
    isLoading,
    error,
    model,
    setModel,
    sendMessage,
    clearConversation,
  } = useAIChat();
  
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Focus input when component mounts
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (input.trim() && !isLoading) {
      sendMessage(input);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  return (
    <div className={`ai-chat-container ${theme}`}>
      <div className="chat-header">
        <div className="header-left">
          <button 
            className="menu-button"
            onClick={() => setIsSettingsOpen(!isSettingsOpen)}
            aria-label={isSettingsOpen ? 'Close settings' : 'Open settings'}
          >
            <Menu size={20} />
          </button>
          <h3>AI Assistant</h3>
        </div>
        <div className="header-actions">
          <button 
            onClick={toggleTheme} 
            className="theme-toggle"
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
          >
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
          <button 
            onClick={onClose} 
            className="close-button"
            aria-label="Close chat"
          >
            <X size={20} />
          </button>
        </div>
      </div>

      <AnimatePresence>
        {isSettingsOpen && (
          <motion.div 
            className="settings-panel"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
          >
            <div className="settings-content">
              <h4>Settings</h4>
              <div className="setting-group">
                <label htmlFor="model-select">AI Model</label>
                <select
                  id="model-select"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  disabled={isLoading}
                >
                  <option value="llama2">Llama 2</option>
                  <option value="mistral">Mistral</option>
                  <option value="codellama">CodeLlama</option>
                </select>
              </div>
              <button 
                onClick={clearConversation}
                disabled={messages.length === 0 || isLoading}
                className="clear-button"
              >
                <Trash2 size={16} /> Clear Conversation
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="messages-container">
        {messages.length === 0 ? (
          <div className="empty-state">
            <MessageSquare size={48} className="empty-icon" />
            <h3>How can I help you today?</h3>
            <p>Ask me anything or let's have a conversation!</p>
          </div>
        ) : (
          <AnimatePresence>
            {messages.map((message, index) => (
              <Message 
                key={`${message.role}-${index}`} 
                message={message} 
                theme={theme}
              />
            ))}
            {isLoading && messages[messages.length - 1]?.role !== 'assistant' && (
              <Message 
                message={{ role: 'assistant', content: '' }} 
                theme={theme}
              />
            )}
            <div ref={messagesEndRef} />
          </AnimatePresence>
        )}
      </div>

      <form onSubmit={handleSubmit} className="input-container">
        <div className="input-wrapper">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a message..."
            rows={1}
            disabled={isLoading}
            aria-label="Type your message"
          />
          <button 
            type="submit" 
            disabled={!input.trim() || isLoading}
            className="send-button"
            aria-label="Send message"
          >
            {isLoading ? (
              <Loader2 size={20} className="spin" />
            ) : (
              <Send size={20} />
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="error-message">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
};

export default AIChat;
