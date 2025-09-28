class OllamaService {
  constructor() {
    this.baseUrl = 'http://localhost:11434';
    this.model = 'llama3'; // Default model
    this.activeRequests = new Map();
  }

  // Check if Ollama is running and get available models
  async checkStatus() {
    try {
      const response = await fetch(`${this.baseUrl}/api/tags`);
      if (!response.ok) throw new Error('Ollama not running');
      const data = await response.json();
      return {
        isRunning: true,
        models: data.models || [],
        currentModel: this.model
      };
    } catch (error) {
      return {
        isRunning: false,
        error: error.message,
        models: [],
        currentModel: null
      };
    }
  }

  // Set the active model
  setModel(model) {
    this.model = model;
    return this.model;
  }

  // Generate a response using the LLM
  async generate(prompt, options = {}) {
    const controller = new AbortController();
    const requestId = Date.now().toString();
    
    // Store the controller for potential cancellation
    this.activeRequests.set(requestId, controller);

    const requestOptions = {
      model: this.model,
      prompt,
      stream: false,
      ...options
    };

    try {
      const response = await fetch(`${this.baseUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestOptions),
        signal: controller.signal
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || 'Failed to generate response');
      }

      const data = await response.json();
      return data.response;
    } catch (error) {
      if (error.name === 'AbortError') {
        throw new Error('Request was cancelled');
      }
      throw error;
    } finally {
      this.activeRequests.delete(requestId);
    }
  }

  // Stream response from the LLM
  async *generateStream(prompt, options = {}) {
    const controller = new AbortController();
    const requestId = Date.now().toString();
    
    // Store the controller for potential cancellation
    this.activeRequests.set(requestId, controller);

    const requestOptions = {
      model: this.model,
      prompt,
      stream: true,
      ...options
    };

    try {
      const response = await fetch(`${this.baseUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestOptions),
        signal: controller.signal
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || 'Failed to generate response');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let done = false;

      while (!done) {
        const { value, done: doneReading } = await reader.read();
        done = doneReading;
        
        if (done) break;
        
        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n').filter(line => line.trim() !== '');
        
        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            if (data.done) {
              done = true;
              break;
            }
            yield data.response;
          } catch (e) {
            console.error('Error parsing stream chunk:', e);
          }
        }
      }
    } catch (error) {
      if (error.name !== 'AbortError') {
        throw error;
      }
    } finally {
      this.activeRequests.delete(requestId);
    }
  }

  // Cancel a specific request
  cancelRequest(requestId) {
    if (this.activeRequests.has(requestId)) {
      this.activeRequests.get(requestId).abort();
      this.activeRequests.delete(requestId);
      return true;
    }
    return false;
  }

  // Cancel all active requests
  cancelAllRequests() {
    this.activeRequests.forEach(controller => controller.abort());
    this.activeRequests.clear();
  }
}

export default new OllamaService();
