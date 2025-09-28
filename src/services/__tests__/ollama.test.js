import OllamaService from '../ollama';

describe('OllamaService', () => {
  let originalFetch;
  
  beforeAll(() => {
    // Store the original fetch implementation
    originalFetch = global.fetch;
    // Mock fetch for all tests
    global.fetch = jest.fn();
  });

  afterEach(() => {
    // Clear all mocks after each test
    jest.clearAllMocks();
  });

  afterAll(() => {
    // Restore the original fetch implementation
    global.fetch = originalFetch;
  });

  describe('checkStatus', () => {
    it('should return available models when Ollama is running', async () => {
      const mockResponse = {
        models: [
          { name: 'llama3', model: 'llama3' },
          { name: 'mistral', model: 'mistral' }
        ]
      };
      
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const result = await OllamaService.checkStatus();
      
      expect(result.isRunning).toBe(true);
      expect(result.models).toHaveLength(2);
      expect(global.fetch).toHaveBeenCalledWith('http://localhost:11434/api/tags');
    });

    it('should handle errors when Ollama is not running', async () => {
      global.fetch.mockRejectedValueOnce(new Error('Connection refused'));
      
      const result = await OllamaService.checkStatus();
      
      expect(result.isRunning).toBe(false);
      expect(result.error).toBe('Connection refused');
    });
  });

  describe('setModel', () => {
    it('should set the active model', () => {
      const newModel = 'mistral';
      const result = OllamaService.setModel(newModel);
      
      expect(result).toBe(newModel);
      expect(OllamaService.model).toBe(newModel);
    });
  });

  describe('generate', () => {
    it('should generate a response with the given prompt', async () => {
      const mockResponse = {
        response: 'This is a test response.'
      };
      
      global.fetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const prompt = 'Test prompt';
      const result = await OllamaService.generate(prompt);
      
      expect(result).toBe(mockResponse.response);
      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:11434/api/generate',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: 'llama3',
            prompt: prompt,
            stream: false
          })
        })
      );
    });

    it('should handle API errors', async () => {
      const errorMessage = 'Invalid API key';
      global.fetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: errorMessage })
      });

      await expect(OllamaService.generate('test')).rejects.toThrow(errorMessage);
    });
  });

  describe('generateStream', () => {
    it('should yield chunks from the streaming response', async () => {
      const mockChunks = [
        'data: { "response": "Hello" }\n\n',
        'data: { "response": " world!" }\n\n',
        'data: [DONE]\n\n'
      ];

      // Mock the response with a ReadableStream
      const mockStream = new ReadableStream({
        start(controller) {
          mockChunks.forEach(chunk => {
            controller.enqueue(new TextEncoder().encode(chunk));
          });
          controller.close();
        }
      });

      global.fetch.mockResolvedValueOnce({
        ok: true,
        body: mockStream
      });

      const prompt = 'Stream test';
      const chunks = [];
      
      for await (const chunk of OllamaService.generateStream(prompt)) {
        chunks.push(chunk);
      }

      expect(chunks).toEqual(['Hello', ' world!']);
    });
  });

  describe('cancelRequest', () => {
    it('should abort an active request', async () => {
      const mockAbortController = {
        abort: jest.fn(),
        signal: {}
      };
      
      // Mock the AbortController
      const originalAbortController = global.AbortController;
      global.AbortController = jest.fn(() => mockAbortController);
      
      // Mock a pending fetch
      global.fetch.mockImplementationOnce(() => new Promise(() => {}));
      
      // Start a request
      const requestPromise = OllamaService.generate('test');
      
      // Cancel the request
      OllamaService.cancelRequest();
      
      // Restore the original AbortController
      global.AbortController = originalAbortController;
      
      // The abort method should have been called
      expect(mockAbortController.abort).toHaveBeenCalled();
      
      // The request should be removed from activeRequests
      expect(OllamaService.activeRequests.size).toBe(0);
      
      // Clean up the pending promise to avoid open handles
      try {
        await requestPromise;
      } catch (error) {
        // Expected error
      }
    });
  });
});
