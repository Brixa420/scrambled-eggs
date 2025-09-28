import React, { useState, useRef, useCallback } from 'react';
import { Send, X, AlertCircle, CheckCircle, Loader2, Download } from 'lucide-react';
import useOllama from '../hooks/useOllama';

const OllamaTest = () => {
  const [prompt, setPrompt] = useState('');
  const [response, setResponse] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);
  const [selectedModel, setSelectedModel] = useState('');
  const [isModelLoading, setIsModelLoading] = useState(false);
  const responseEndRef = useRef(null);

  const {
    isReady,
    isGenerating,
    error,
    models,
    currentModel,
    generate,
    generateStream,
    cancelGeneration,
    checkStatus,
    setModel,
    isLoading: isStatusLoading
  } = useOllama();

  // Set the selected model when currentModel changes
  React.useEffect(() => {
    if (currentModel && !selectedModel) {
      setSelectedModel(currentModel);
    }
  }, [currentModel, selectedModel]);

  // Auto-scroll to bottom of response
  React.useEffect(() => {
    if (responseEndRef.current) {
      responseEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [response]);

  // Handle model change
  const handleModelChange = async (e) => {
    const model = e.target.value;
    setSelectedModel(model);
    
    if (model !== currentModel) {
      try {
        setIsModelLoading(true);
        await setModel(model);
        setResponse(prev => prev + `\n\nSwitched to model: ${model}\n`);
      } catch (err) {
        console.error('Error changing model:', err);
        setResponse(prev => prev + `\n\nError: ${err.message}\n`);
      } finally {
        setIsModelLoading(false);
      }
    }
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!prompt.trim() || !isReady || isGenerating) return;

    const userPrompt = `User: ${prompt}\n\n`;
    setResponse(prev => prev + userPrompt + 'AI: ');
    setPrompt('');
    setIsStreaming(true);

    try {
      await generateStream(
        prompt,
        {
          model: selectedModel || currentModel,
          temperature: 0.7,
          max_tokens: 2000,
        },
        (chunk, fullResponse) => {
          setResponse(prev => {
            // Only append the new chunk to the last line
            const lines = prev.split('\n');
            const lastLine = lines[lines.length - 1];
            return prev.slice(0, -lastLine.length) + fullResponse;
          });
        },
        (fullResponse) => {
          setResponse(prev => prev + '\n\n');
        }
      );
    } catch (err) {
      if (err.name !== 'AbortError') {
        setResponse(prev => prev + `\n\nError: ${err.message}\n`);
      }
    } finally {
      setIsStreaming(false);
    }
  };

  // Handle manual refresh
  const handleRefresh = async () => {
    setResponse('');
    await checkStatus();
  };

  // Handle cancel generation
  const handleCancel = () => {
    cancelGeneration();
    setIsStreaming(false);
    setResponse(prev => prev + '\n\n[Generation cancelled]\n');
  };

  return (
    <div className="flex flex-col h-full bg-white dark:bg-gray-900 rounded-lg shadow-lg overflow-hidden">
      {/* Header */}
      <div className="bg-blue-600 dark:bg-blue-800 text-white p-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold">Ollama LLM Test</h2>
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${isReady ? 'bg-green-500' : 'bg-red-500'}`} />
            <span className="text-sm">
              {isReady ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
        
        <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
          <div className="flex items-center">
            <span className="text-blue-200 mr-1">Model:</span>
            <select
              value={selectedModel || ''}
              onChange={handleModelChange}
              disabled={isModelLoading || isGenerating}
              className="bg-blue-700 text-white rounded px-2 py-1 text-sm border-0 focus:ring-2 focus:ring-blue-400"
            >
              {models.map((model) => (
                <option key={model.name} value={model.name}>
                  {model.name} ({(model.size / 1e9).toFixed(1)}GB)
                </option>
              ))}
            </select>
            {isModelLoading && (
              <Loader2 className="ml-2 h-4 w-4 animate-spin" />
            )}
          </div>
          
          <button
            onClick={handleRefresh}
            disabled={isStatusLoading}
            className="flex items-center text-blue-200 hover:text-white transition-colors"
            title="Refresh models"
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${isStatusLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Status Bar */}
      {error && (
        <div className="bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 p-2 text-sm flex items-center">
          <AlertCircle className="h-4 w-4 mr-2" />
          {error}
        </div>
      )}

      {/* Response Area */}
      <div className="flex-1 p-4 overflow-y-auto bg-gray-50 dark:bg-gray-800">
        {!response ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-500 dark:text-gray-400">
            <div className="text-center p-6 max-w-md">
              <h3 className="text-lg font-medium mb-2">Ollama LLM Test</h3>
              <p className="text-sm mb-4">
                {isReady
                  ? 'Enter a prompt and press Send to test the LLM.'
                  : 'Connecting to Ollama...'}
              </p>
              {!isReady && (
                <div className="flex items-center justify-center">
                  <Loader2 className="h-6 w-6 animate-spin mr-2" />
                  <span>Checking Ollama status...</span>
                </div>
              )}
            </div>
          </div>
        ) : (
          <pre className="whitespace-pre-wrap font-sans text-sm text-gray-800 dark:text-gray-200">
            {response}
            {isStreaming && (
              <span className="inline-block w-2 h-4 bg-blue-500 animate-pulse"></span>
            )}
            <div ref={responseEndRef} />
          </pre>
        )}
      </div>

      {/* Input Area */}
      <form onSubmit={handleSubmit} className="p-4 border-t border-gray-200 dark:border-gray-700">
        <div className="flex items-end space-x-2">
          <div className="flex-1 relative">
            <textarea
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Enter your prompt here..."
              className="w-full p-3 pr-12 text-gray-900 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
              rows={3}
              disabled={!isReady || isGenerating}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSubmit(e);
                }
              }}
            />
            <div className="absolute right-2 bottom-2 flex space-x-1">
              {isGenerating ? (
                <button
                  type="button"
                  onClick={handleCancel}
                  className="p-1 text-red-500 hover:text-red-600 dark:hover:text-red-400"
                  title="Stop generation"
                >
                  <X className="h-5 w-5" />
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!prompt.trim() || !isReady || isGenerating}
                  className="p-1 text-blue-500 hover:text-blue-600 dark:hover:text-blue-400 disabled:opacity-50 disabled:cursor-not-allowed"
                  title="Send message"
                >
                  <Send className="h-5 w-5" />
                </button>
              )}
            </div>
          </div>
        </div>
        
        <div className="mt-2 text-xs text-gray-500 dark:text-gray-400 flex justify-between items-center">
          <div>
            {isReady ? (
              <span className="text-green-600 dark:text-green-400 flex items-center">
                <CheckCircle className="h-3 w-3 mr-1" />
                Ollama is connected
              </span>
            ) : (
              <span className="text-yellow-600 dark:text-yellow-400 flex items-center">
                <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                Connecting to Ollama...
              </span>
            )}
          </div>
          <div>
            {currentModel && (
              <span className="text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-1 rounded">
                {currentModel}
              </span>
            )}
          </div>
        </div>
      </form>
    </div>
  );
};

export default OllamaTest;
