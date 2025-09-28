import { useState, useEffect, useCallback, useRef } from 'react';
import ollamaService from '../services/ollama';

export const useOllama = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState(null);
  const [models, setModels] = useState([]);
  const [currentModel, setCurrentModel] = useState(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const activeRequest = useRef(null);

  // Check Ollama status and load models
  const checkStatus = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const status = await ollamaService.checkStatus();
      setModels(status.models);
      setCurrentModel(status.currentModel || null);
      setIsReady(status.isRunning);
      
      if (!status.isRunning) {
        setError('Ollama is not running. Please make sure Ollama is installed and running.');
      }
      
      return status;
    } catch (err) {
      console.error('Error checking Ollama status:', err);
      setError('Failed to connect to Ollama. Please make sure it is running.');
      setIsReady(false);
      return { isRunning: false, models: [] };
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Set the active model
  const setModel = useCallback((model) => {
    const newModel = ollamaService.setModel(model);
    setCurrentModel(newModel);
    return newModel;
  }, []);

  // Generate a response (non-streaming)
  const generate = useCallback(async (prompt, options = {}) => {
    if (!isReady) {
      throw new Error('Ollama is not ready');
    }

    setIsGenerating(true);
    setError(null);
    
    try {
      const response = await ollamaService.generate(prompt, options);
      return response;
    } catch (err) {
      console.error('Error generating response:', err);
      setError(err.message);
      throw err;
    } finally {
      setIsGenerating(false);
    }
  }, [isReady]);

  // Generate a streaming response
  const generateStream = useCallback(async (prompt, options = {}, onChunk, onComplete) => {
    if (!isReady) {
      throw new Error('Ollama is not ready');
    }

    setIsGenerating(true);
    setError(null);
    
    try {
      const requestId = Date.now().toString();
      activeRequest.current = requestId;
      
      let fullResponse = '';
      
      for await (const chunk of ollamaService.generateStream(prompt, options)) {
        if (activeRequest.current !== requestId) {
          // Request was cancelled
          return;
        }
        
        fullResponse += chunk;
        
        if (onChunk) {
          onChunk(chunk, fullResponse);
        }
      }
      
      if (onComplete) {
        onComplete(fullResponse);
      }
      
      return fullResponse;
    } catch (err) {
      if (err.name !== 'AbortError') {
        console.error('Error generating stream:', err);
        setError(err.message);
        throw err;
      }
    } finally {
      if (activeRequest.current) {
        activeRequest.current = null;
      }
      setIsGenerating(false);
    }
  }, [isReady]);

  // Cancel the current generation
  const cancelGeneration = useCallback(() => {
    if (activeRequest.current) {
      ollamaService.cancelRequest(activeRequest.current);
      activeRequest.current = null;
      setIsGenerating(false);
      return true;
    }
    return false;
  }, []);

  // Check status on mount
  useEffect(() => {
    checkStatus();
    
    // Cleanup on unmount
    return () => {
      if (activeRequest.current) {
        cancelGeneration();
      }
    };
  }, [checkStatus, cancelGeneration]);

  return {
    // State
    isLoading,
    isReady,
    error,
    models,
    currentModel,
    isGenerating,
    
    // Actions
    checkStatus,
    setModel,
    generate,
    generateStream,
    cancelGeneration,
    
    // Aliases for convenience
    isConnected: isReady,
    isProcessing: isGenerating,
    availableModels: models,
    activeModel: currentModel,
  };
};

export default useOllama;
