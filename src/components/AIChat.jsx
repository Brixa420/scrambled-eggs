import React, { useState, useRef, useEffect, useContext } from 'react';
import { Mic, Send, X, Bot, Volume2, VolumeX, Loader2, AlertCircle } from 'lucide-react';
import { AppContext } from '../context/AppContext';

const AIChat = ({ onClose }) => {
    const { networkStatus } = useContext(AppContext);
  
  const [messages, setMessages] = useState([
    { 
      id: 1, 
      sender: 'ai', 
      text: 'Hello! I am your AI assistant. How can I help you today?', 
      timestamp: new Date(),
      status: 'delivered'
    }
  ]);
  
  const [inputText, setInputText] = useState('');
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const messagesEndRef = useRef(null);
  const recognitionRef = useRef(null);

  // Initialize speech recognition
  useEffect(() => {
    if ('webkitSpeechRecognition' in window) {
      recognitionRef.current = new window.webkitSpeechRecognition();
      recognitionRef.current.continuous = false;
      recognitionRef.current.interimResults = false;
      recognitionRef.current.lang = 'en-US';

      recognitionRef.current.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        setInputText(transcript);
        handleSendMessage(transcript);
      };

      recognitionRef.current.onend = () => {
        setIsListening(false);
      };
    }

    return () => {
      if (recognitionRef.current) {
        recognitionRef.current.stop();
      }
    };
  }, []);

  const handleSendMessage = async (text = inputText) => {
    if (!text.trim()) return;

    // Add user message to UI immediately
    const userMessage = {
      id: Date.now(),
      sender: 'user',
      text: text,
      timestamp: new Date()
    };
    
    setMessages(prev => [...prev, userMessage]);
    setInputText('');
    
    try {
      // Add a loading indicator
      const loadingMessage = {
        id: `loading-${Date.now()}`,
        sender: 'ai',
        text: '...',
        timestamp: new Date(),
        isLoading: true
      };
      
      setMessages(prev => [...prev, loadingMessage]);
      
      // Call your backend API endpoint that handles the OpenAI integration
      const response = await fetch('http://localhost:3001/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.REACT_APP_OPENAI_API_KEY}`
        },
        body: JSON.stringify({
          message: text,
          // Include conversation history for context
          history: messages
            .filter(msg => msg.sender === 'ai' || msg.sender === 'user')
            .map(msg => ({
              role: msg.sender === 'user' ? 'user' : 'assistant',
              content: msg.text
            }))
        })
      });

      if (!response.ok) {
        throw new Error('Failed to get response from AI service');
      }

      const data = await response.json();
      
      // Remove loading indicator
      setMessages(prev => prev.filter(msg => !msg.isLoading));
      
      // Add AI response
      const aiResponse = {
        id: Date.now() + 1,
        sender: 'ai',
        text: data.response || "I'm sorry, I couldn't process your request.",
        timestamp: new Date()
      };
      
      setMessages(prev => [...prev, aiResponse]);
      speak(aiResponse.text);
      
    } catch (error) {
      console.error('Error calling AI service:', error);
      
      // Remove loading indicator
      setMessages(prev => prev.filter(msg => !msg.isLoading));
      
      // Show error message
      const errorMessage = {
        id: Date.now() + 1,
        sender: 'ai',
        text: "I'm having trouble connecting to the AI service. Please try again later.",
        timestamp: new Date(),
        isError: true
      };
      
      setMessages(prev => [...prev, errorMessage]);
    }
  };

  const toggleVoiceInput = () => {
    if (isListening) {
      recognitionRef.current.stop();
      setIsListening(false);
    } else {
      recognitionRef.current.start();
      setIsListening(true);
    }
  };

  const speak = (text) => {
    if ('speechSynthesis' in window) {
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = 1.0;
      utterance.pitch = 1.0;
      utterance.onstart = () => setIsSpeaking(true);
      utterance.onend = () => setIsSpeaking(false);
      window.speechSynthesis.speak(utterance);
    }
  };

  const stopSpeaking = () => {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
      setIsSpeaking(false);
    }
  };

  // Auto-scroll to bottom of messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  return (
    <div className="fixed bottom-4 right-4 w-96 bg-gray-900 border border-purple-700 rounded-xl shadow-2xl overflow-hidden flex flex-col z-50">
      {/* Header */}
      <div className="bg-gradient-to-r from-purple-900 to-indigo-900 p-3 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <Bot className="h-5 w-5 text-purple-300" />
          <h3 className="font-semibold text-white">AI Assistant</h3>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={isSpeaking ? stopSpeaking : () => speak(messages[messages.length - 1].text)}
            className="p-1.5 rounded-full hover:bg-purple-800 transition-colors"
            title={isSpeaking ? "Stop speaking" : "Read last message"}
          >
            {isSpeaking ? (
              <VolumeX className="h-4 w-4 text-red-400" />
            ) : (
              <Volume2 className="h-4 w-4 text-purple-300" />
            )}
          </button>
          <button
            onClick={onClose}
            className="p-1.5 rounded-full hover:bg-purple-800 transition-colors"
          >
            <X className="h-4 w-4 text-purple-300" />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 p-4 space-y-4 overflow-y-auto max-h-96">
        {messages.map((message) => (
          <div
            key={message.id}
            className={`flex ${message.sender === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[80%] p-3 rounded-lg ${
                message.sender === 'user'
                  ? 'bg-purple-600 text-white'
                  : 'bg-gray-800 text-gray-100'
              }`}
            >
              <p className="text-sm">{message.text}</p>
              <p className="text-xs opacity-60 mt-1">
                {new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </p>
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-3 border-t border-gray-800">
        <div className="flex items-center gap-2">
          <button
            onClick={toggleVoiceInput}
            className={`p-2 rounded-full ${
              isListening
                ? 'bg-red-500 text-white'
                : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
            } transition-colors`}
            title={isListening ? "Listening..." : "Voice input"}
          >
            <Mic className="h-5 w-5" />
          </button>
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
            placeholder="Type your message..."
            className="flex-1 bg-gray-800 text-white rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
          <button
            onClick={() => handleSendMessage()}
            disabled={!inputText.trim()}
            className="p-2 bg-purple-600 text-white rounded-full hover:bg-purple-700 disabled:opacity-50 transition-colors"
            title="Send message"
          >
            <Send className="h-5 w-5" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default AIChat;
