import React, { useState, useEffect, useRef } from 'react';
import clippy from '../../services/clippy/ClippyAI';
import './Clippy.css';

const Clippy = () => {
  const [isVisible, setIsVisible] = useState(false);
  const [messages, setMessages] = useState([]);
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef(null);
  const clippyRef = useRef(null);
  const [position, setPosition] = useState({ x: 50, y: 50 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

  // Initialize Clippy
  useEffect(() => {
    clippy.on('message', handleNewMessage);
    clippy.on('animate', handleAnimation);
    
    // Show Clippy after a short delay
    const timer = setTimeout(() => {
      setIsVisible(true);
      clippy.init();
    }, 3000);

    return () => {
      clearTimeout(timer);
      clippy.off('message', handleNewMessage);
      clippy.off('animate', handleAnimation);
    };
  }, []);

  // Handle new messages from Clippy
  const handleNewMessage = (message) => {
    setIsTyping(true);
    
    // Simulate typing effect
    setTimeout(() => {
      setMessages(prev => [...prev, { ...message, id: Date.now() }]);
      setIsTyping(false);
      scrollToBottom();
    }, 500);
  };

  // Handle animations
  const handleAnimation = (animation) => {
    // You can add animation logic here
    console.log('Animation:', animation);
  };

  // Handle user input
  const handleUserInput = (e) => {
    if (e.key === 'Enter' && e.target.value.trim()) {
      const text = e.target.value.trim();
      clippy.handleInput(text);
      e.target.value = '';
    }
  };

  // Scroll to bottom of messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // Dragging functionality
  const handleMouseDown = (e) => {
    if (e.button !== 0) return; // Only left click
    const rect = clippyRef.current.getBoundingClientRect();
    setDragOffset({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    });
    setIsDragging(true);
  };

  const handleMouseMove = (e) => {
    if (!isDragging) return;
    
    setPosition({
      x: e.clientX - dragOffset.x,
      y: e.clientY - dragOffset.y
    });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  // Toggle Clippy visibility
  const toggleClippy = () => {
    setIsVisible(!isVisible);
  };

  if (!isVisible) {
    return (
      <div 
        className="clippy-minimized"
        onClick={toggleClippy}
        style={{ left: '20px', bottom: '20px' }}
      >
        <div className="clippy-icon">📎</div>
      </div>
    );
  }

  return (
    <div 
      ref={clippyRef}
      className="clippy-container"
      style={{ left: `${position.x}px`, top: `${position.y}px` }}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      <div className="clippy-header" onMouseDown={handleMouseDown}>
        <div className="clippy-title">Clippy Assistant</div>
        <button className="clippy-close" onClick={toggleClippy}>×</button>
      </div>
      
      <div className="clippy-messages">
        {messages.map(msg => (
          <div key={msg.id} className={`clippy-message clippy-${msg.type}`}>
            <div className="clippy-avatar">📎</div>
            <div className="clippy-text">{msg.text}</div>
          </div>
        ))}
        {isTyping && (
          <div className="clippy-message clippy-typing">
            <div className="clippy-avatar">📎</div>
            <div className="clippy-typing-indicator">
              <span></span>
              <span></span>
              <span></span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>
      
      <div className="clippy-input-container">
        <input
          type="text"
          className="clippy-input"
          placeholder="Type a message..."
          onKeyPress={handleUserInput}
        />
        <button className="clippy-send">→</button>
      </div>
      
      <div className="clippy-actions">
        <button onClick={() => clippy.handleInput('/help')}>Help</button>
        <button onClick={() => clippy.handleInput('/mood excited')}>Change Mood</button>
        <button onClick={() => clippy.handleInput('/anarchy')}>Toggle Anarchy</button>
      </div>
    </div>
  );
};

export default Clippy;
