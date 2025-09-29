import { useState, useEffect, useCallback } from 'react';
import { ollamaService } from '../services/ai/OllamaService';

export const useAIChat = (initialModel = 'llama2') => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [model, setModel] = useState(initialModel);
  const [isTyping, setIsTyping] = useState(false);

  // Load conversation history
  useEffect(() => {
    const history = ollamaService.getHistory();
    if (history.length > 0) {
      setMessages(history);
    }
  }, []);

  // Handle streaming responses
  useEffect(() => {
    const handleToken = ({ token, fullResponse, done }) => {
      setMessages(prev => {
        const lastMessage = prev[prev.length - 1];
        if (lastMessage?.role === 'assistant' && !lastMessage.complete) {
          return [
            ...prev.slice(0, -1),
            { ...lastMessage, content: fullResponse, complete: done }
          ];
        }
        return prev;
      });
    };

    const handleGenerationStart = () => {
      setIsLoading(true);
      setError(null);
      setMessages(prev => [
        ...prev,
        { role: 'assistant', content: '', complete: false }
      ]);
    };

    const handleGenerationComplete = () => {
      setIsLoading(false);
      setIsTyping(false);
    };

    const handleError = (error) => {
      console.error('AI Service Error:', error);
      setError(error.message || 'Failed to get response from AI');
      setIsLoading(false);
      setIsTyping(false);
    };

    ollamaService.on('token', handleToken);
    ollamaService.on('generationStart', handleGenerationStart);
    ollamaService.on('generationComplete', handleGenerationComplete);
    ollamaService.on('error', handleError);

    return () => {
      ollamaService.off('token', handleToken);
      ollamaService.off('generationStart', handleGenerationStart);
      ollamaService.off('generationComplete', handleGenerationComplete);
      ollamaService.off('error', handleError);
    };
  }, []);

  const sendMessage = useCallback(async (message) => {
    if (!message.trim()) return;
    
    setIsLoading(true);
    setInput('');
    
    // Add user message to the chat
    const userMessage = { role: 'user', content: message };
    setMessages(prev => [...prev, userMessage]);
    
    try {
      await ollamaService.sendMessage(message, model, {
        context: ollamaService.getHistory().map(m => ({
          role: m.role,
          content: m.content
        }))
      });
    } catch (error) {
      console.error('Error sending message:', error);
      setError(error.message || 'Failed to send message');
      setIsLoading(false);
    }
  }, [model]);

  const clearConversation = useCallback(() => {
    ollamaService.clearHistory();
    setMessages([]);
    setError(null);
  }, []);

  return {
    messages,
    input,
    setInput,
    isLoading,
    error,
    model,
    setModel,
    sendMessage,
    clearConversation,
    isTyping
  };
};
