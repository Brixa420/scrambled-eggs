import { EventEmitter } from 'events';

class OllamaService extends EventEmitter {
  constructor() {
    super();
    this.baseUrl = 'http://localhost:11434';
    this.conversationHistory = [];
    this.isGenerating = false;
  }

  async sendMessage(message, model = 'llama2', options = {}) {
    const payload = {
      model,
      prompt: message,
      stream: true,
      context: options.context || [],
      ...options
    };

    this.isGenerating = true;
    this.emit('generationStart');

    try {
      const response = await fetch(`${this.baseUrl}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Ollama API error: ${response.statusText}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let fullResponse = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n').filter(line => line.trim() !== '');

        for (const line of lines) {
          try {
            const data = JSON.parse(line);
            if (data.response) {
              fullResponse += data.response;
              this.emit('token', {
                token: data.response,
                fullResponse,
                done: data.done
              });
            }
          } catch (e) {
            console.error('Error parsing Ollama response:', e);
          }
        }
      }

      this.addToHistory({
        role: 'user',
        content: message
      });
      
      this.addToHistory({
        role: 'assistant',
        content: fullResponse
      });

      this.emit('generationComplete', fullResponse);
      return fullResponse;
    } catch (error) {
      console.error('Error calling Ollama API:', error);
      this.emit('error', error);
      throw error;
    } finally {
      this.isGenerating = false;
    }
  }

  addToHistory(message) {
    this.conversationHistory.push({
      ...message,
      timestamp: new Date().toISOString()
    });
    this.emit('historyUpdate', this.conversationHistory);
  }

  clearHistory() {
    this.conversationHistory = [];
    this.emit('historyUpdate', this.conversationHistory);
  }

  getHistory() {
    return [...this.conversationHistory];
  }
}

export const ollamaService = new OllamaService();
